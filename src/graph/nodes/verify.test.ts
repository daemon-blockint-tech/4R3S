/**
 * Tests for the VERIFY node's prompt budget.
 *
 * The invariant: a verdict may only address a finding the critic was actually
 * shown. The rendered block is fenced, and the fence has a budget — so a long
 * finding list used to be cut while the instruction line still asked for a
 * verdict per finding and `coerceVerdicts` still accepted every index below the
 * total. Verdicts then landed on findings the critic never saw, deleting real
 * ones and confirming unseen ones into durable memory.
 *
 * The assertions therefore compare, per prompt, the indices asked for against
 * the indices rendered — not just "it did not crash".
 */
import { describe, it, expect } from "vitest";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";

import { makeVerifyNode } from "./verify.js";
import { coerceFindings } from "../util.js";
import { CrystallineStore } from "../../memory/crystalline-store.js";
import type { AresState, Finding } from "../state.js";

/** Enough findings, each with realistic evidence, to overflow the fence budget. */
function overflowingFindings(count = 20, evidenceChars = 1200): Finding[] {
  return coerceFindings(
    Array.from({ length: count }, (_, i) => ({
      vulnClass: `vuln-${i}`,
      location: "src/lib.rs:1",
      severity: "high",
      category: "missing-signer-check",
      // A distinct marker per finding so a prompt can be searched for it.
      evidence: `MARKER-${i} ${"e".repeat(evidenceChars)}`,
      remediation: "fix it",
    })),
    "heuristic",
  );
}

/** The human prompt text of one chat invocation. */
function humanText(messages: unknown): string {
  const list = messages as { content?: unknown }[];
  return String(list[list.length - 1]?.content ?? "");
}

/**
 * A critic that records each prompt and rejects the FIRST finding of every
 * batch it is shown. Rejecting a per-batch index is what exercises the offset:
 * a batch's index 0 is not the report's finding 0.
 */
function capturingCritic(): { chat: BaseChatModel; prompts: string[] } {
  const prompts: string[] = [];
  const chat = {
    async invoke(messages: unknown) {
      prompts.push(humanText(messages));
      return {
        content: JSON.stringify({
          verdicts: [
            { index: 0, status: "false-positive", confidence: "high", reason: "no" },
          ],
        }),
      };
    },
  } as unknown as BaseChatModel;
  return { chat, prompts };
}

function deps(chat: BaseChatModel) {
  return {
    chat,
    crystalline: new CrystallineStore(),
    retriever: { retrieve: async () => [] } as never,
  };
}

function stateWith(mergedFindings: Finding[]): AresState {
  return { request: "audit", mergedFindings } as unknown as AresState;
}

/** Indices the instruction line asks the critic to rule on. */
function askedRange(prompt: string): number[] {
  const m = prompt.match(/referencing each index \(0\.\.(\d+)\)/);
  if (!m) throw new Error("prompt has no index range instruction");
  return Array.from({ length: Number(m[1]) + 1 }, (_, i) => i);
}

/** Indices actually rendered as findings in the prompt. */
function renderedIndices(prompt: string): number[] {
  return [...prompt.matchAll(/^(\d+)\. \[/gm)].map((m) => Number(m[1]));
}

describe("verify: the critic is never asked about a finding it was not shown", () => {
  it("splits an over-budget finding list instead of truncating it", async () => {
    const findings = overflowingFindings();
    const { chat, prompts } = capturingCritic();

    await makeVerifyNode(deps(chat))(stateWith(findings));

    for (const prompt of prompts) {
      // The invariant: nothing was cut, so every index the critic is asked
      // about is a finding it was actually shown, with its evidence intact.
      expect(prompt).not.toContain("[truncated at fence budget]");
      expect(renderedIndices(prompt)).toEqual(askedRange(prompt));
    }

    // The list does not fit one prompt — if it ever does, this test is no
    // longer exercising the overflow and the fixture needs to grow.
    expect(prompts.length).toBeGreaterThan(1);

    // Batching, not sampling: every finding was reviewed exactly once.
    const joined = prompts.join("\n");
    for (let i = 0; i < findings.length; i += 1) {
      expect(joined.split(`MARKER-${i} `)).toHaveLength(2);
    }
  });

  it("maps each batch's verdict indices back onto the right findings", async () => {
    const findings = overflowingFindings();
    const { chat, prompts } = capturingCritic();

    const out = await makeVerifyNode(deps(chat))(stateWith(findings));

    // The critic rejected index 0 of each batch. Without the per-batch offset
    // those verdicts would all land on the report's first finding, leaving the
    // findings that were actually rejected in the report.
    const rejected = prompts.map((p) => {
      const m = p.match(/MARKER-(\d+) /);
      return `vuln-${m![1]}`;
    });
    expect(new Set(rejected).size).toBe(prompts.length);

    const kept = out.verifiedFindings!.map((f) => f.vulnClass);
    expect(kept).toHaveLength(findings.length - prompts.length);
    for (const vulnClass of rejected) {
      expect(kept).not.toContain(vulnClass);
    }
  });

  it("counts one LLM turn per batch", async () => {
    const findings = overflowingFindings();
    const { chat, prompts } = capturingCritic();

    const out = await makeVerifyNode(deps(chat))(stateWith(findings));

    // `iterations` bounds runaway loops, so it has to reflect the calls made.
    expect(out.iterations).toBe(prompts.length);
  });

  it("still sends a short list as a single prompt", async () => {
    const { chat, prompts } = capturingCritic();

    const out = await makeVerifyNode(deps(chat))(stateWith(overflowingFindings(3)));

    expect(prompts).toHaveLength(1);
    expect(askedRange(prompts[0]!)).toEqual([0, 1, 2]);
    expect(out.verifiedFindings).toHaveLength(2);
  });

  it("keeps batches intact when evidence smuggles fence markers", async () => {
    // `fenceUntrusted` rewrites `<<END>>` (7 chars) into `[fence marker
    // removed]` (22), so a batch packed by raw length can be pushed past the
    // budget by the audited party's own text — cutting the tail of a block the
    // critic is still told to rule on. Sized to fit the budget raw (~16k) and
    // to blow it once rewritten (~50k), which is the case a raw measurement
    // cannot see.
    const findings = coerceFindings(
      Array.from({ length: 8 }, (_, i) => ({
        vulnClass: `vuln-${i}`,
        location: "src/lib.rs:1",
        severity: "high",
        category: "missing-signer-check",
        evidence: `MARKER-${i} ${"<<END>>".repeat(280)}`,
        remediation: "fix it",
      })),
      "heuristic",
    );
    const { chat, prompts } = capturingCritic();

    await makeVerifyNode(deps(chat))(stateWith(findings));

    for (const prompt of prompts) {
      expect(prompt).not.toContain("[truncated at fence budget]");
      expect(renderedIndices(prompt)).toEqual(askedRange(prompt));
    }
  });

  it("keeps the blank lines that separate the instruction, the data, and the range", async () => {
    // `.filter(Boolean)` dropped both `""` entries from the prompt array,
    // because an empty string is falsy — the three sections ran together as one
    // block of lines. The fence markers still delimited the untrusted data, so
    // nothing was mis-parsed and no verdict landed on the wrong finding; the
    // separators were simply written deliberately and silently absent.
    const { chat, prompts } = capturingCritic();

    await makeVerifyNode(deps(chat))(stateWith(overflowingFindings(2, 20)));

    expect(prompts).toHaveLength(1);
    const prompt = prompts[0]!;
    // A blank line before the fence and after it, not merely somewhere.
    expect(prompt).toMatch(/\n\nDraft findings to review/);
    expect(prompt).toMatch(/END UNTRUSTED DATA>>>\n\nReturn one verdict/);
  });

  it("makes no call and returns nothing for an empty finding list", async () => {
    const { chat, prompts } = capturingCritic();

    const out = await makeVerifyNode(deps(chat))(stateWith([]));

    expect(prompts).toHaveLength(0);
    expect(out.verifiedFindings).toEqual([]);
  });
});
