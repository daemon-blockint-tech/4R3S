"""Fingerprinting for source-clone detection, by winnowing.

Implements the winnowing algorithm from Schleimer, Wilkerson & Aiken, "Winnowing:
Local Algorithms for Document Fingerprinting" (SIGMOD 2003) — the algorithm
behind MOSS. Named and citable rather than invented, following the convention
`services/risk` set for a task card that names no source to port from: implement
a published methodology the way `services/cve/severity.py` implements CVSS v3.1.

Deterministic and hermetic: no LLM, no network, no randomness. Winnowing was
chosen over MinHash and SimHash partly for that — those need hash permutations
or random projections, and a clustering result that shifts between runs cannot
be reproduced from committed data (GOLDEN RULE 3, and "Hermetic by default" in
SECURITY.md).

## The guarantee, and its price

Winnowing has two parameters and a published guarantee that ties them together:

- ``k`` — the noise threshold. A match shorter than ``k`` characters is *never*
  reported. This is what stops `let mut i = 0;` from making every Solana program
  a clone of every other.
- ``t`` — the guarantee threshold. A match of ``t`` characters or longer is
  *always* detected.
- The window size follows: ``w = t - k + 1``.

Matches between ``k`` and ``t`` are detected probabilistically. That middle band
is a real limitation, not a rounding error, and it is why
:func:`similarity` returns a score to be interpreted rather than a boolean.

## What this catches, and what it does not

Fingerprints are taken over source that has been stripped of comments and had
its whitespace collapsed (see :func:`normalize`). So this detects:

- verbatim copies
- copies with reformatting, reindentation, or comment changes

It does **not** detect a copy whose identifiers were renamed — `vault_balance`
to `pool_balance` changes the k-grams and therefore the fingerprints. In the
clone-detection literature those are type-2 clones; catching them needs
tokenisation with identifier normalisation, which is a larger claim than this
module makes. Saying so matters: a detector that silently misses renamed forks,
while a caller believes otherwise, is worse than one whose limits are written
down.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# Chosen, not tuned: k must exceed the length of the boilerplate that legitimately
# recurs across unrelated Anchor programs. `#[program]`, `pub fn initialize(ctx:
# Context<Initialize>) -> Result<()> {`, and `require!(...)` lines all sit under
# 40 normalised characters. t is set so the window stays small enough that a
# short handler still contributes several fingerprints.
DEFAULT_K = 40
DEFAULT_T = 80

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_WHITESPACE = re.compile(r"\s+")


def normalize(source: str) -> str:
    """Strip comments and collapse whitespace.

    Deliberately conservative. Identifiers, literals and structure are left
    alone, so a renamed fork will not match — see the module docstring. Doing
    more here (renaming identifiers to placeholders, say) would change what
    class of clone this module claims to find, and that claim should be made
    explicitly rather than acquired by accident.

    Comments go first because a fork often diverges only in its comments, and
    leaving them in would let a copied program score as original by having its
    header rewritten.
    """
    without_block = _BLOCK_COMMENT.sub(" ", source)
    without_line = _LINE_COMMENT.sub(" ", without_block)
    return _WHITESPACE.sub(" ", without_line).strip()


def _stable_hash(text: str) -> int:
    """A hash of ``text`` that is the same for the same input in every
    process, forever — not just within one run.

    Deliberately not Python's own ``hash()``: CPython randomizes ``str``
    hashing per process by default (``PYTHONHASHSEED``, on since 3.3, as a
    hash-flood DoS mitigation), so ``hash()`` on the identical k-gram text
    returns a *different* integer in every fresh process. That silently
    breaks this module's own determinism claim (GOLDEN RULE 3): winnowing
    selects the *minimum* hash per window, so a different seed can select a
    different representative k-gram, which changes the fingerprint set,
    which changes the Jaccard score — confirmed directly, the same pair of
    programs scored anywhere from 0.32 to 0.53 across five separate process
    runs before this fix, straddling ``DEFAULT_THRESHOLD`` (0.55) in
    practice. BLAKE2b has no such per-process seed: the same string hashes
    to the same digest in this run, the next run, and next year's CI run.
    Truncated to 8 bytes — winnowing only needs a total order to pick a
    minimum from, not the full 32-byte digest.
    """
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=8).digest(), "big")


def _kgram_hashes(text: str, k: int) -> list[int]:
    """Hashes of every length-``k`` substring, in order.

    Uses :func:`_stable_hash` on the substring rather than a rolling hash:
    the input here is one source file, not a web-scale corpus, and a rolling
    hash would add an arithmetic-overflow surface for no measurable gain at
    this size.
    """
    if len(text) < k:
        return []
    return [_stable_hash(text[i : i + k]) for i in range(len(text) - k + 1)]


def fingerprint(source: str, k: int = DEFAULT_K, t: int = DEFAULT_T) -> set[int]:
    """Winnowed fingerprints of ``source``.

    Raises ``ValueError`` for parameters that break the algorithm's guarantee
    rather than silently returning something. ``t < k`` would ask for a
    guarantee on matches shorter than the noise threshold, which is
    contradictory; a caller that reaches that state has a bug upstream and
    should be told, not handed an empty set that reads as "no similarity".
    """
    if k < 1:
        raise ValueError(f"k must be at least 1, got {k}")
    if t < k:
        raise ValueError(f"t ({t}) must be >= k ({k}): a guarantee threshold below the noise threshold is contradictory")

    normalized = normalize(source)
    hashes = _kgram_hashes(normalized, k)
    if not hashes:
        return set()

    window = t - k + 1
    if window <= 1:
        # Every k-gram is its own window, so winnowing selects all of them.
        # Not an error: it is what w = t - k + 1 yields when t == k, and the
        # result is still a valid (if larger) fingerprint set.
        return set(hashes)

    selected: set[int] = set()
    # Winnowing selects the minimum hash in each window, breaking ties by taking
    # the rightmost occurrence — the paper's rule. The tie-break is not
    # cosmetic: taking the leftmost instead selects more fingerprints than
    # necessary from runs of equal hashes, inflating density above the density
    # the guarantee is derived for.
    for start in range(len(hashes) - window + 1):
        chunk = hashes[start : start + window]
        minimum = min(chunk)
        # Rightmost index of the minimum within this window.
        rightmost = len(chunk) - 1 - chunk[::-1].index(minimum)
        selected.add(chunk[rightmost])
    return selected


def similarity(left: set[int], right: set[int]) -> float:
    """Jaccard similarity of two fingerprint sets, in ``[0.0, 1.0]``.

    Two empty sets return ``0.0``, not ``1.0``. Set-theoretically the Jaccard
    index of two empty sets is undefined and often defined as 1; here that would
    mean two files too short to fingerprint are reported as identical, which
    would propagate vulnerability flags between programs about which nothing is
    known. The safe direction for an undefined comparison is "no evidence of
    similarity".
    """
    if not left or not right:
        return 0.0
    intersection = len(left & right)
    union = len(left | right)
    return intersection / union


@dataclass(frozen=True)
class Program:
    """One program available for comparison."""

    program_id: str
    source: str


@dataclass(frozen=True)
class Fingerprinted:
    """A program with its fingerprints computed once."""

    program_id: str
    fingerprints: frozenset[int]
    #: Normalised length, so a caller can tell "no fingerprints because the file
    #: was tiny" from "no fingerprints because something went wrong".
    normalized_chars: int


def fingerprint_programs(
    programs: list[Program], k: int = DEFAULT_K, t: int = DEFAULT_T
) -> list[Fingerprinted]:
    """Fingerprint each program once.

    Separate from clustering so the O(n) hashing is not repeated inside the
    O(n²) pairwise comparison, and so a caller can inspect which programs
    produced no fingerprints at all before drawing conclusions from a clustering
    run that quietly excluded them.
    """
    out: list[Fingerprinted] = []
    for p in programs:
        normalized = normalize(p.source)
        out.append(
            Fingerprinted(
                program_id=p.program_id,
                fingerprints=frozenset(fingerprint(p.source, k, t)),
                normalized_chars=len(normalized),
            )
        )
    return out
