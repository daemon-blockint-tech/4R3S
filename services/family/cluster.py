"""Program-family clustering, and propagating vulnerability flags to forks.

Groups programs whose source is similar enough to be copies of one another, then
carries a vulnerability known in one member across to the others.

## The part that needs care

Propagating a flag from A to B produces a statement about B that was never
observed in B. That is exactly the kind of claim the rest of this repository is
built to refuse: GOLDEN RULE 3 ("no trust-me numbers"), the verify-claims gate,
`analyze-heuristic.ts`'s `speculative` demotion for a finding that cites a file
the run never read, and `known-programs.ts`'s downgrade of findings against
canonical programs.

So an inherited flag is never presented as a finding in the fork. It is returned
as an :class:`InheritedFlag` carrying the similarity score, the program it came
from, and evidence that names the inference rather than describing the fork's
code. Callers are expected to render it as "worth checking because it resembles
X", never as "present in B". A caller that flattens these into the same list as
observed findings has undone the point of the type.

There is no similarity threshold above which an inherited flag becomes a
confirmed one. Even byte-identical source can differ in the account constraints
its deployment enforces, and the fork may carry the fix. Confirming requires
reading the fork — which is what the auditor pipeline does, and what this service
deliberately does not attempt.

## Clustering method

Single-linkage: A and B join a cluster if their pairwise similarity clears the
threshold, and clusters merge transitively. Chosen because the relation being
modelled — "was copied from" — is itself transitive: if B is a fork of A and C is
a fork of B, C belongs in A's family even where C and A have drifted past the
threshold directly.

The cost is chaining: a long chain of small drifts puts two dissimilar programs
in one cluster. That is accepted deliberately, and it is another reason the
inherited flag records the *pairwise* similarity to the specific program the flag
came from, rather than a cluster-level average that would hide the weak link.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fingerprint import (
    DEFAULT_K,
    DEFAULT_T,
    Fingerprinted,
    Program,
    fingerprint_programs,
    similarity,
)

#: Pairwise Jaccard similarity at or above which two programs are treated as
#: family. Set high on purpose: the cost of a false grouping here is a
#: vulnerability flag attached to a program that does not have it, and an
#: auditor's attention spent ruling it out. A missed grouping costs a hint.
DEFAULT_THRESHOLD = 0.55

#: A fingerprint appearing in more than this fraction of the corpus is treated as
#: boilerplate and discarded before similarity is computed.
#:
#: This exists because of a failure the tests caught: two unrelated Anchor
#: programs, sharing only `use anchor_lang::prelude::*`, `declare_id!`,
#: `#[program]` and a `#[derive(Accounts)]` struct, scored 0.76 — comfortably
#: past the threshold — and a vulnerability flag propagated between them. The
#: boilerplate was most of the text, so it was most of the fingerprints.
#:
#: Discarding corpus-wide fingerprints is how MOSS handles the same problem for
#: shared assignment template code, so this stays within the methodology the
#: module already cites rather than adding an invented correction.
DEFAULT_MAX_DOCUMENT_FREQUENCY = 0.5

#: Document-frequency filtering needs enough programs for "appears in most of
#: them" to mean anything. With two programs, every shared fingerprint appears in
#: 100% of the corpus, so filtering would discard exactly the evidence of
#: copying it is meant to preserve.
#:
#: Below this size, filtering is skipped and boilerplate is NOT separated from
#: copying. That is a real limitation of a small corpus, not something the
#: algorithm can resolve: with two files there is no way to tell a shared
#: preamble from a shared origin. A caller comparing a handful of programs should
#: expect boilerplate to inflate similarity, and should either widen the corpus
#: or raise `threshold`.
MIN_CORPUS_FOR_DF_FILTER = 4


@dataclass(frozen=True)
class VulnFlag:
    """A vulnerability observed in one specific program."""

    program_id: str
    category: str
    severity: str
    #: What was actually seen, in that program. Carried through unchanged so an
    #: inherited flag can show the reader what the original evidence was.
    evidence: str


@dataclass(frozen=True)
class InheritedFlag:
    """A vulnerability flag carried to a fork. Not a finding.

    ``similarity`` is the pairwise score against ``inherited_from``, not a
    cluster average, so a reader can see how strong the specific link is.
    """

    program_id: str
    category: str
    severity: str
    inherited_from: str
    similarity: float
    #: Names the inference. Deliberately not phrased as an observation about
    #: ``program_id``'s code, because nothing was read from it.
    evidence: str
    #: Fixed, so it cannot be dropped by a caller assembling its own text.
    unverified: bool = True


@dataclass
class Cluster:
    """A family of programs, and the flags inherited within it."""

    members: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.members)


@dataclass(frozen=True)
class ClusterResult:
    clusters: list[Cluster]
    #: Programs that produced no fingerprints — too short to compare. Reported
    #: separately rather than emitted as singleton clusters, because "not
    #: comparable" and "compared and matched nothing" are different facts and
    #: collapsing them would hide files the run could not actually assess.
    unfingerprintable: list[str]
    #: Programs whose every fingerprint was corpus-wide boilerplate. Nothing
    #: distinctive remained to compare, which is a different fact from being too
    #: short to fingerprint — reported separately so neither is mistaken for
    #: "compared and matched nothing".
    boilerplate_only: list[str]
    #: Every pairwise score at or above the threshold, for auditability: a
    #: cluster on its own does not show why its members were joined.
    links: list[tuple[str, str, float]]


def boilerplate_fingerprints(
    fingerprinted: list[Fingerprinted],
    max_document_frequency: float = DEFAULT_MAX_DOCUMENT_FREQUENCY,
) -> frozenset[int]:
    """Fingerprints common enough across the corpus to carry no signal.

    Returns empty below :data:`MIN_CORPUS_FOR_DF_FILTER`, where document
    frequency cannot distinguish a shared preamble from a shared origin.
    Returning empty rather than raising keeps a two-program comparison working;
    the docstring on the constant states what is lost.
    """
    comparable = [f for f in fingerprinted if f.fingerprints]
    if len(comparable) < MIN_CORPUS_FOR_DF_FILTER:
        return frozenset()

    counts: dict[int, int] = {}
    for f in comparable:
        for fp in f.fingerprints:
            counts[fp] = counts.get(fp, 0) + 1

    limit = max_document_frequency * len(comparable)
    return frozenset(fp for fp, n in counts.items() if n > limit)


def cluster_programs(
    programs: list[Program],
    threshold: float = DEFAULT_THRESHOLD,
    k: int = DEFAULT_K,
    t: int = DEFAULT_T,
    max_document_frequency: float = DEFAULT_MAX_DOCUMENT_FREQUENCY,
) -> ClusterResult:
    """Group programs into families by pairwise source similarity."""
    if not 0.0 < threshold <= 1.0:
        # A threshold of 0 would put every program in one family; there is no
        # reading of the input under which a caller means that.
        raise ValueError(f"threshold must be in (0.0, 1.0], got {threshold}")

    fingerprinted = fingerprint_programs(programs, k, t)
    boilerplate = boilerplate_fingerprints(fingerprinted, max_document_frequency)

    # Distinguished from `unfingerprintable`: a program whose every fingerprint
    # was corpus-wide boilerplate has nothing distinctive left to compare, which
    # is a different fact from being too short to fingerprint at all.
    distinctive: dict[str, set[int]] = {
        f.program_id: set(f.fingerprints) - boilerplate for f in fingerprinted
    }

    comparable = [f for f in fingerprinted if distinctive[f.program_id]]
    unfingerprintable = [f.program_id for f in fingerprinted if not f.fingerprints]
    boilerplate_only = [
        f.program_id
        for f in fingerprinted
        if f.fingerprints and not distinctive[f.program_id]
    ]

    # Union-find over comparable programs, giving single-linkage transitively.
    parent: dict[str, str] = {f.program_id: f.program_id for f in comparable}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path halving
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    links: list[tuple[str, str, float]] = []
    for i, left in enumerate(comparable):
        for right in comparable[i + 1 :]:
            score = similarity(distinctive[left.program_id], distinctive[right.program_id])
            if score >= threshold:
                links.append((left.program_id, right.program_id, score))
                union(left.program_id, right.program_id)

    grouped: dict[str, list[str]] = {}
    for f in comparable:
        grouped.setdefault(find(f.program_id), []).append(f.program_id)

    # Sorted so a run is reproducible and two runs can be diffed. Dict iteration
    # order follows insertion here, which follows input order — stable in
    # practice, but relying on it would make the output depend on how a caller
    # happened to order its arguments.
    clusters = [Cluster(members=sorted(m)) for m in grouped.values()]
    clusters.sort(key=lambda c: (-len(c.members), c.members[0]))

    return ClusterResult(
        clusters=clusters,
        unfingerprintable=sorted(unfingerprintable),
        boilerplate_only=sorted(boilerplate_only),
        links=sorted(links, key=lambda l: (-l[2], l[0], l[1])),
    )


def propagate_flags(
    result: ClusterResult,
    flags: list[VulnFlag],
    programs: list[Program],
    threshold: float = DEFAULT_THRESHOLD,
    k: int = DEFAULT_K,
    t: int = DEFAULT_T,
) -> list[InheritedFlag]:
    """Carry each flag to the other members of its cluster.

    Recomputes fingerprints so the pairwise similarity attached to each
    inherited flag is the real score between *those two* programs, rather than
    the fact that both ended up in one cluster. Under single linkage those are
    not the same thing, and reporting the cluster as evidence would overstate a
    chained link.

    A flag whose program is not in any cluster, or is alone in its cluster,
    propagates nowhere and produces no output — silence rather than a
    zero-similarity entry, which would read as a considered non-finding.
    """
    by_id = {p.program_id: p for p in programs}
    all_fp = fingerprint_programs(list(by_id.values()), k, t)
    # Same boilerplate filter as clustering, so the score attached to an
    # inherited flag is the score that put the two programs in one family. A
    # raw-fingerprint score here would be higher than the one clustering used,
    # and the flag would overstate the link that justified it.
    boilerplate = boilerplate_fingerprints(all_fp)
    fingerprints = {
        f.program_id: set(f.fingerprints) - boilerplate for f in all_fp
    }

    cluster_of: dict[str, Cluster] = {}
    for cluster in result.clusters:
        for member in cluster.members:
            cluster_of[member] = cluster

    inherited: list[InheritedFlag] = []
    for flag in flags:
        cluster = cluster_of.get(flag.program_id)
        if cluster is None or len(cluster) < 2:
            continue

        source_fp = fingerprints.get(flag.program_id, set())
        for member in cluster.members:
            if member == flag.program_id:
                continue
            score = similarity(source_fp, fingerprints.get(member, set()))
            inherited.append(
                InheritedFlag(
                    program_id=member,
                    category=flag.category,
                    severity=flag.severity,
                    inherited_from=flag.program_id,
                    similarity=score,
                    evidence=(
                        f"Not observed in {member}. Inherited from {flag.program_id}, "
                        f"whose normalised source has Jaccard similarity {score:.2f} to "
                        f"this program's under winnowing (k={k}, t={t}). The original "
                        f"evidence was: {flag.evidence}"
                    ),
                )
            )

    # Most-similar first: the strongest link is the one worth checking first.
    inherited.sort(key=lambda f: (-f.similarity, f.program_id, f.category))
    return inherited
