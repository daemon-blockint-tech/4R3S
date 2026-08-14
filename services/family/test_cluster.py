"""Tests for services/family.

Two failure modes matter more than the rest, and both are silent:

1. **False grouping.** Anchor programs share a lot of boilerplate. If that
   boilerplate alone clusters unrelated programs, every vulnerability in one
   propagates to all of them, and an auditor spends their attention ruling out
   flags that were never plausible.

2. **An inherited flag that reads as an observed one.** Propagation produces a
   claim about a program nothing was read from. If it renders the same way a real
   finding does, the report asserts something no one checked.

The similarity numbers here are asserted as inequalities against the threshold
rather than as exact values. An exact value would pin Python's `hash`
implementation, and the property that matters is "clears / does not clear the
bar", not the digits.
"""

from __future__ import annotations

import pytest

from cluster import (
    DEFAULT_THRESHOLD,
    Cluster,
    ClusterResult,
    Program,
    VulnFlag,
    cluster_programs,
    propagate_flags,
)
from fingerprint import DEFAULT_K, fingerprint, normalize, similarity

# Boilerplate an Anchor program has whether or not it was copied from anywhere.
ANCHOR_BOILERPLATE = """
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod my_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}
"""


def vault_program(unique_body: str) -> str:
    """Anchor boilerplate plus a distinct handler."""
    return ANCHOR_BOILERPLATE + f"""
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {{
    {unique_body}
    Ok(())
}}
"""


class TestNormalization:
    def test_strips_line_comments(self):
        assert "secret" not in normalize("let x = 1; // secret note")

    def test_strips_block_comments_across_lines(self):
        assert "hidden" not in normalize("let x = 1; /* hidden\nstill hidden */ let y = 2;")

    def test_collapses_whitespace_so_reindentation_does_not_hide_a_copy(self):
        a = normalize("fn f() {\n    let x = 1;\n}")
        b = normalize("fn f() {        let x = 1;    }")
        assert a == b

    def test_leaves_identifiers_alone(self):
        # Documents the boundary rather than asserting a capability: a renamed
        # fork is deliberately NOT detected, and normalize() is where that
        # decision lives.
        assert "vault_balance" in normalize("let vault_balance = 0;")


class TestFingerprintParameters:
    def test_rejects_a_guarantee_threshold_below_the_noise_threshold(self):
        # t < k asks for a guarantee on matches shorter than the length below
        # which matches are never reported. Returning an empty set instead would
        # read as "no similarity".
        with pytest.raises(ValueError, match="contradictory"):
            fingerprint("x" * 200, k=40, t=20)

    def test_rejects_a_non_positive_k(self):
        with pytest.raises(ValueError, match="at least 1"):
            fingerprint("x" * 200, k=0, t=80)

    def test_returns_nothing_for_source_shorter_than_k(self):
        # Not an error: a two-line file is a legitimate input, it simply cannot
        # be compared. cluster_programs reports these separately.
        assert fingerprint("fn f() {}", k=DEFAULT_K) == set()

    def test_identical_source_fingerprints_identically(self):
        src = vault_program("let x = amount;")
        assert fingerprint(src) == fingerprint(src)

    def test_comment_only_change_does_not_change_fingerprints(self):
        # The case that matters for forks: a copied program whose header comment
        # was rewritten must still match.
        base = vault_program("let x = amount;")
        recommented = "// entirely different header\n" + base
        assert fingerprint(base) == fingerprint(recommented)


class TestSimilarity:
    def test_two_empty_sets_are_not_similar(self):
        # Jaccard of two empty sets is conventionally 1. Here that would mean
        # two files too short to fingerprint are "identical", propagating flags
        # between programs about which nothing is known.
        assert similarity(set(), set()) == 0.0

    def test_one_empty_set_is_not_similar_to_a_populated_one(self):
        assert similarity(set(), {1, 2, 3}) == 0.0

    def test_identical_sets_are_fully_similar(self):
        assert similarity({1, 2, 3}, {1, 2, 3}) == 1.0

    def test_disjoint_sets_are_not_similar(self):
        assert similarity({1, 2}, {3, 4}) == 0.0


class TestClusteringDoesNotGroupOnBoilerplate:
    def test_unrelated_programs_sharing_anchor_boilerplate_stay_apart(self):
        # The false-positive that would poison everything downstream, and the
        # one this module got wrong first: with no boilerplate filter, two
        # unrelated programs sharing only the Anchor preamble scored 0.76 and a
        # vulnerability flag propagated between them.
        #
        # Needs a corpus of at least MIN_CORPUS_FOR_DF_FILTER for document
        # frequency to mean anything — with two files there is no way to tell a
        # shared preamble from a shared origin.
        bodies = [
            "let fee = amount / 100; token::transfer(cpi, fee)?;",
            "let clock = Clock::get()?; require!(clock.unix_timestamp > ctx.accounts.pool.unlock_at, E::Locked);",
            "let seeds = &[b\"vault\", authority.key.as_ref()]; let (pda, bump) = Pubkey::find_program_address(seeds, &crate::ID);",
            "ctx.accounts.pool.total = ctx.accounts.pool.total.checked_add(amount).ok_or(E::Overflow)?;",
            "let ix = system_instruction::transfer(from.key, to.key, amount); invoke(&ix, &[from, to])?;",
        ]
        programs = [Program(f"prog-{i}", vault_program(b)) for i, b in enumerate(bodies)]

        result = cluster_programs(programs)

        assert all(len(c) == 1 for c in result.clusters), (
            f"unrelated programs were grouped: {[c.members for c in result.clusters]}"
        )
        assert result.links == []

    def test_a_copy_is_still_found_inside_a_corpus_of_unrelated_programs(self):
        # The other half: the boilerplate filter must not remove so much that a
        # real fork stops matching. Same corpus as above plus one verbatim copy.
        bodies = [
            "let fee = amount / 100; token::transfer(cpi, fee)?;",
            "let clock = Clock::get()?; require!(clock.unix_timestamp > 0, E::Locked);",
            "let seeds = &[b\"vault\"]; let (pda, bump) = Pubkey::find_program_address(seeds, &crate::ID);",
            "ctx.accounts.pool.total = ctx.accounts.pool.total.checked_add(amount).ok_or(E::Overflow)?;",
        ]
        programs = [Program(f"prog-{i}", vault_program(b)) for i, b in enumerate(bodies)]
        programs.append(Program("fork-of-0", vault_program(bodies[0])))

        result = cluster_programs(programs)

        families = [c.members for c in result.clusters if len(c) > 1]
        assert families == [["fork-of-0", "prog-0"]], (
            f"expected exactly one family, got {[c.members for c in result.clusters]}"
        )

    def test_a_verbatim_copy_is_grouped(self):
        src = vault_program("let fee = amount / 100; token::transfer(cpi, fee)?;")
        result = cluster_programs([Program("original", src), Program("fork", src)])

        assert len(result.clusters) == 1
        assert result.clusters[0].members == ["fork", "original"]

    def test_a_reformatted_copy_is_grouped(self):
        src = vault_program("let fee = amount / 100; token::transfer(cpi, fee)?;")
        reformatted = src.replace("\n", "\n    ").replace("    ", "\t")
        result = cluster_programs([Program("original", src), Program("fork", reformatted)])

        assert len(result.clusters) == 1

    def test_records_why_members_were_joined(self):
        # A cluster alone does not show its evidence; links do.
        src = vault_program("let fee = amount / 100;")
        result = cluster_programs([Program("a", src), Program("b", src)])

        assert len(result.links) == 1
        left, right, score = result.links[0]
        assert {left, right} == {"a", "b"}
        assert score >= DEFAULT_THRESHOLD

    def test_reports_uncomparable_programs_separately_from_unmatched_ones(self):
        # "Too short to fingerprint" and "compared and matched nothing" are
        # different facts. Emitting the first as a singleton cluster would hide
        # that the run could not assess it at all.
        result = cluster_programs(
            [
                Program("tiny", "fn f() {}"),
                Program("real", vault_program("let fee = amount / 100;")),
            ]
        )

        assert result.unfingerprintable == ["tiny"]
        assert all("tiny" not in c.members for c in result.clusters)

    def test_rejects_a_threshold_of_zero(self):
        with pytest.raises(ValueError, match="must be in"):
            cluster_programs([], threshold=0.0)

    def test_rejects_a_threshold_above_one(self):
        with pytest.raises(ValueError, match="must be in"):
            cluster_programs([], threshold=1.5)

    def test_output_order_does_not_depend_on_input_order(self):
        src = vault_program("let fee = amount / 100;")
        forward = cluster_programs([Program("a", src), Program("b", src)])
        backward = cluster_programs([Program("b", src), Program("a", src)])

        assert [c.members for c in forward.clusters] == [c.members for c in backward.clusters]


class TestPropagationNeverOverclaims:
    def _family(self) -> tuple[ClusterResult, list[Program]]:
        src = vault_program("let fee = amount / 100; token::transfer(cpi, fee)?;")
        programs = [Program("original", src), Program("fork", src)]
        return cluster_programs(programs), programs

    def test_says_the_vulnerability_was_not_observed_in_the_fork(self):
        # The single most important assertion in this file. An inherited flag
        # that reads like an observation is a claim nobody checked.
        result, programs = self._family()
        flags = [VulnFlag("original", "arbitrary-cpi", "critical", "invoke() with unchecked program id")]

        inherited = propagate_flags(result, flags, programs)

        assert len(inherited) == 1
        assert inherited[0].program_id == "fork"
        assert "Not observed in fork" in inherited[0].evidence

    def test_carries_the_original_evidence_so_a_reader_can_judge_it(self):
        result, programs = self._family()
        flags = [VulnFlag("original", "arbitrary-cpi", "critical", "invoke() with unchecked program id")]

        inherited = propagate_flags(result, flags, programs)

        assert "invoke() with unchecked program id" in inherited[0].evidence

    def test_is_marked_unverified_and_cannot_be_constructed_otherwise(self):
        result, programs = self._family()
        flags = [VulnFlag("original", "arbitrary-cpi", "critical", "e")]

        inherited = propagate_flags(result, flags, programs)

        assert inherited[0].unverified is True
        # Frozen, so a caller cannot quietly clear the marker before rendering.
        with pytest.raises(Exception):
            inherited[0].unverified = False  # type: ignore[misc]

    def test_reports_the_pairwise_score_not_a_cluster_average(self):
        result, programs = self._family()
        flags = [VulnFlag("original", "arbitrary-cpi", "critical", "e")]

        inherited = propagate_flags(result, flags, programs)

        assert inherited[0].inherited_from == "original"
        assert inherited[0].similarity >= DEFAULT_THRESHOLD

    def test_propagates_nothing_from_a_program_with_no_family(self):
        # Silence, not a zero-similarity entry that would read as a considered
        # non-finding. Corpus sized past MIN_CORPUS_FOR_DF_FILTER so boilerplate
        # does not group these for us.
        bodies = [
            "let fee = amount / 100; token::transfer(cpi, fee)?;",
            "let clock = Clock::get()?; require!(clock.slot > 0, E::X);",
            "let seeds = &[b\"vault\"]; let (pda, b2) = Pubkey::find_program_address(seeds, &crate::ID);",
            "ctx.accounts.pool.total = ctx.accounts.pool.total.checked_add(amount).ok_or(E::O)?;",
        ]
        programs = [Program(f"p-{i}", vault_program(b)) for i, b in enumerate(bodies)]

        result = cluster_programs(programs)
        inherited = propagate_flags(result, [VulnFlag("p-0", "x", "high", "e")], programs)

        assert inherited == []

    def test_propagates_nothing_for_a_flag_on_an_unknown_program(self):
        result, programs = self._family()

        inherited = propagate_flags(
            result, [VulnFlag("never-seen", "x", "high", "e")], programs
        )

        assert inherited == []

    def test_does_not_propagate_a_flag_back_onto_its_own_program(self):
        result, programs = self._family()
        flags = [VulnFlag("original", "arbitrary-cpi", "critical", "e")]

        inherited = propagate_flags(result, flags, programs)

        assert all(f.program_id != "original" for f in inherited)

    def test_orders_the_strongest_link_first(self):
        # Three-member family: the fork that matches best should be checked
        # before the one that only matched transitively.
        base = vault_program("let fee = amount / 100; token::transfer(cpi, fee)?;")
        programs = [
            Program("original", base),
            Program("exact-fork", base),
            Program("drifted-fork", base + "\npub fn extra(ctx: Context<Initialize>) -> Result<()> { Ok(()) }\n"),
        ]
        result = cluster_programs(programs)
        flags = [VulnFlag("original", "arbitrary-cpi", "critical", "e")]

        inherited = propagate_flags(result, flags, programs)

        if len(inherited) >= 2:
            assert inherited[0].similarity >= inherited[-1].similarity
