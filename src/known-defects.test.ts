/**
 * Known-defect register.
 *
 * Each case below asserts the behaviour ARES *should* have and is marked
 * `it.fails`, because today it does not. That inversion is deliberate: the file
 * passes on the current code, and the moment someone fixes one of these bugs
 * Vitest reports "expected test to fail, but it passed" — which is the signal to
 * delete the `.fails` marker and keep the assertion as a real regression test.
 * Asserting the buggy behaviour directly would instead punish the fix.
 *
 * These are cross-cutting rather than per-module, so they live in one file
 * instead of beside each unit. Every case was reproduced against the real code
 * paths — none is hypothetical.
 */
import { describe, it, expect, vi } from "vitest";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";

import { cosineSimilarity } from "./memory/crystalline-store.js";
import { CrystallineStore } from "./memory/crystalline-store.js";
import { makeMergeNode } from "./graph/nodes/merge.js";
import { makeRememberNode } from "./graph/nodes/remember.js";
import { coerceFindings } from "./graph/util.js";
import type { AresState, Finding } from "./graph/state.js";
import type { KnowledgeWriter } from "./persistence/knowledge-writer.js";

/** A chat stub returning a fixed body for every call. */
function chatReturning(body: string): BaseChatModel {
  return {
    async invoke() {
      return { content: body };
    },
  } as unknown as BaseChatModel;
}

describe("MERGE drops findings whose location the model omitted", () => {
  /**
   * `coerceFindings` defaults a missing `location` to "" (graph/util.ts), and
   * MERGE keys dedupe on `vulnClass + location` (graph/nodes/merge.ts). So when
   * a model omits `location` — which nothing forces it to supply — every finding
   * sharing a vulnClass collapses onto one key and all but one are discarded
   * with no log line and no counter. Two distinct overflow sites in different
   * instructions become one reported finding.
   */
  it.fails("keeps two distinct findings that both lack a location", async () => {
    const raw = [
      {
        vulnClass: "integer-overflow",
        severity: "high",
        evidence: "unchecked add in deposit()",
        remediation: "checked_add",
        category: "integer-overflow-underflow",
      },
      {
        vulnClass: "integer-overflow",
        severity: "high",
        evidence: "unchecked sub in withdraw()",
        remediation: "checked_sub",
        category: "integer-overflow-underflow",
      },
    ];
    const findings = coerceFindings({ findings: raw }, "heuristic");
    expect(findings.map((f) => f.location)).toEqual(["", ""]);

    const merged = await makeMergeNode()({ findings } as AresState);

    // Two separate bugs were found; two should survive.
    expect(merged.mergedFindings).toHaveLength(2);
  });
});

describe("cosineSimilarity hides an embedding dimension mismatch", () => {
  /**
   * crystalline-store.ts returns 0 when the vectors differ in length, which is
   * the same value it returns for "genuinely unrelated". Change
   * EMBEDDINGS_MODEL and every stored vector keeps its old dimension: recall
   * then scores 0 against everything and quietly returns nothing, while the
   * report still says the knowledge source was consulted successfully.
   */
  it.fails("does not silently score a mismatched vector as merely dissimilar", () => {
    const sameDim = cosineSimilarity([1, 0, 0], [1, 0, 0]);
    expect(sameDim).toBe(1);

    // A 3-dim query against a 4-dim stored vector is a configuration error,
    // not a similarity of zero. It must be distinguishable from this:
    const genuinelyUnrelated = cosineSimilarity([1, 0, 0], [0, 1, 0]);
    expect(genuinelyUnrelated).toBe(0);

    // Any fix counts — throwing, NaN, or a sentinel — so long as a mismatch no
    // longer reads as "unrelated". Capturing the throw keeps this assertion
    // honest whichever route the fix takes.
    const mismatch = (): number | "threw" => {
      try {
        return cosineSimilarity([1, 0, 0], [1, 0, 0, 0]);
      } catch {
        return "threw";
      }
    };
    expect(mismatch()).not.toBe(0);
  });
});

describe("REMEMBER persists knowledge derived from unconfirmed findings", () => {
  /**
   * VERIFY fails open: `applyVerdicts` keeps any finding the model returned no
   * verdict for and marks it "suspected" (graph/util.ts). REMEMBER then reads
   * `state.verifiedFindings` and feeds every one of them to the model without
   * consulting `status` (graph/nodes/remember.ts), so a finding that was never
   * confirmed — possibly a hallucination — becomes durable memory that RECALL
   * replays into future audits' prompts. That is the memory-poisoning loop.
   */
  it.fails("does not write memory derived from a merely suspected finding", async () => {
    const suspected: Finding = {
      vulnClass: "missing-signer",
      location: "ix:withdraw",
      severity: "critical",
      evidence: "no is_signer check observed",
      remediation: "add a Signer constraint",
      source: "heuristic",
      category: "missing-signer-check",
      speculative: true,
      confidence: "low",
      status: "suspected",
    };

    const persist = vi.fn().mockResolvedValue(undefined);
    const knowledge: KnowledgeWriter = { enabled: true, persist };
    const crystalline = new CrystallineStore();

    const remember = makeRememberNode({
      chat: chatReturning(
        JSON.stringify([
          { level: 3, content: "program X omits signer checks on withdraw", tags: ["x"] },
        ]),
      ),
      crystalline,
      retriever: { retrieve: async () => [] } as never,
      knowledge,
    });

    const out = await remember({
      verifiedFindings: [suspected],
      intake: { target: "Prog111", depth: "standard", concerns: [], summary: "s" },
    } as AresState);

    // Nothing unconfirmed should reach durable memory.
    expect(out.memoryWrites).toHaveLength(0);
    expect(persist).not.toHaveBeenCalled();
  });
});
