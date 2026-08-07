/**
 * Tests for the REPORT node.
 *
 * report.ts's stated design is that the severity table, finding ids, and
 * coverage figures are computed in code and handed to the model as fact to
 * reproduce — not left for the model to derive or count. Nothing verified that
 * before this file: a regression that let the model recompute any of these
 * would still produce a report that reads fine, and would only be caught by a
 * human comparing numbers by hand.
 *
 * `fallbackReport` — the path exercised when synthesis itself fails — had no
 * test at all despite being the one output a caller sees when the model call
 * errors.
 */
import { describe, it, expect } from "vitest";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";

import { makeReportNode, fallbackReport } from "./report.js";
import { CrystallineStore } from "../../memory/crystalline-store.js";
import type { AresState, Finding } from "../state.js";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    vulnClass: "narrowing cast",
    location: "src/withdraw.rs:2",
    severity: "high",
    evidence: "let small = amount as u64;",
    remediation: "use try_into()",
    source: "heuristic",
    category: "unsafe-type-cast",
    speculative: false,
    confidence: "high",
    ...overrides,
  };
}

/** A chat that echoes back whatever human message it received. */
function echoingChat(): { chat: BaseChatModel; lastPrompt: () => string } {
  let last = "";
  const chat = {
    async invoke(messages: unknown) {
      last = JSON.stringify(messages);
      return { content: "REPORT BODY" };
    },
  } as unknown as BaseChatModel;
  return { chat, lastPrompt: () => last };
}

/** A chat that always throws, to exercise the failure path. */
function throwingChat(message: string): BaseChatModel {
  return {
    async invoke() {
      throw new Error(message);
    },
  } as unknown as BaseChatModel;
}

function deps(chat: BaseChatModel) {
  return {
    chat,
    crystalline: new CrystallineStore(),
    retriever: { retrieve: async () => [] } as never,
  };
}

function baseState(overrides: Partial<AresState> = {}): AresState {
  return {
    request: "audit",
    recalled: [],
    mergedFindings: [],
    verifiedFindings: [],
    analyzers: [],
    retrieval: [],
    coverage: [],
    ...overrides,
  } as unknown as AresState;
}

describe("report node: severity and ids are computed in code", () => {
  it("assigns ARES-001, ARES-002 in the order findings are given, not by severity", async () => {
    // Order is the input order (already most-severe-first by the time REPORT
    // runs), not re-sorted here — a regression that re-sorted would silently
    // change which finding a stakeholder calls "ARES-001" between runs.
    const findings = [
      finding({ vulnClass: "first-finding-marker", severity: "critical" }),
      finding({ vulnClass: "second-finding-marker", severity: "low" }),
    ];
    const { chat, lastPrompt } = echoingChat();

    await makeReportNode(deps(chat))(
      baseState({ mergedFindings: findings, verifiedFindings: findings }),
    );

    const prompt = lastPrompt();
    // Assert each finding's own line carries its own id, not merely that
    // "ARES-001" occurs somewhere in the prompt: a mutation that made
    // formatFindingId return a constant ("ARES-001" for every finding) was
    // caught only by this stronger form — the weaker "toContain + relative
    // position" version below passed even under that mutation, because
    // finding text still appeared in input order regardless of what id label
    // was attached to it.
    const lineFor = (marker: string) => {
      const idx = prompt.indexOf(marker);
      expect(idx).toBeGreaterThan(-1);
      return prompt.slice(Math.max(0, idx - 40), idx);
    };
    expect(lineFor("first-finding-marker")).toContain("ARES-001");
    expect(lineFor("second-finding-marker")).toContain("ARES-002");
    expect(lineFor("second-finding-marker")).not.toContain("ARES-001");
  });

  it("computes the severity distribution from findings, not from a model claim", async () => {
    const findings = [
      finding({ severity: "critical" }),
      finding({ severity: "critical" }),
      finding({ severity: "low" }),
    ];
    const { chat, lastPrompt } = echoingChat();

    await makeReportNode(deps(chat))(
      baseState({ mergedFindings: findings, verifiedFindings: findings }),
    );

    const prompt = lastPrompt();
    // severitySummaryTable's own format — this is what proves the table
    // handed to the model came from severityDistribution(), not a description
    // asking the model to count.
    expect(prompt).toContain("| Critical | 2 |");
    expect(prompt).toContain("| Low | 1 |");
    expect(prompt).toContain("**Total** | **3**");
  });

  it("reports how many findings verification dropped as false positives", async () => {
    const merged = [finding(), finding({ vulnClass: "dropped" })];
    const verified = [merged[0]!];
    const { chat, lastPrompt } = echoingChat();

    await makeReportNode(deps(chat))(
      baseState({ mergedFindings: merged, verifiedFindings: verified }),
    );

    expect(lastPrompt()).toContain("1 dropped as false-positive");
  });
});

describe("report node: coverage is presented as claimed, not measured", () => {
  it("labels coverage as analyzer-asserted even when every class is claimed", async () => {
    // The dangerous case is not empty coverage — it's full coverage from a
    // black-box run, which reads as thorough unless explicitly qualified.
    const { chat, lastPrompt } = echoingChat();

    await makeReportNode(deps(chat))(
      baseState({ coverage: ["missing-signer-check", "arbitrary-cpi"] }),
    );

    const prompt = lastPrompt();
    expect(prompt).toContain("ANALYZER-ASSERTED, not measured");
    expect(prompt).toContain("Do not");
    expect(prompt).toMatch(/describe it as measured or verified/);
  });

  it("states plainly when no source was read, rather than omitting the point", async () => {
    const { chat, lastPrompt } = echoingChat();

    await makeReportNode(deps(chat))(baseState({ source: { available: false } as never }));

    expect(lastPrompt()).toContain("Source read: NONE");
    expect(lastPrompt()).toContain("black-box review");
  });
});

describe("report node: the assurance banner cannot be skipped", () => {
  it("prepends a banner when an analyzer failed, regardless of model output", async () => {
    const { chat } = echoingChat();

    const out = await makeReportNode(deps(chat))(
      baseState({
        analyzers: [{ analyzer: "static", outcome: "failed", detail: "tool crashed" }],
      }),
    );

    // The model returned "REPORT BODY" with no banner text of its own — if the
    // banner appears, it was added by withAssuranceBanner, not the model.
    expect(out.report).toContain("REPORT BODY");
    expect(out.report!.length).toBeGreaterThan("REPORT BODY".length);
  });

  it("adds no banner only when every one of the four analyzers reported ok", async () => {
    // assuranceBanner treats an analyzer that never reported at all
    // (missingAnalyzers) the same as one that reported failed/degraded —
    // silence is not evidence of a clean run. All four names in
    // ANALYZER_ORDER must be present and "ok" for the banner to be omitted.
    const { chat } = echoingChat();

    const out = await makeReportNode(deps(chat))(
      baseState({
        analyzers: [
          { analyzer: "onchain", outcome: "ok" },
          { analyzer: "static", outcome: "ok" },
          { analyzer: "heuristic", outcome: "ok" },
          { analyzer: "cua", outcome: "ok" },
        ],
        retrieval: [{ source: "crystalline", outcome: "ok" } as never],
      }),
    );

    expect(out.report).toBe("REPORT BODY");
  });

  it("still adds a banner if even one of the four analyzers is simply absent from the report", async () => {
    // The regression this guards against: an analyzer silently not running
    // (e.g. a node skipped by a graph bug) must not read as a clean report
    // just because none of the analyzers that DID run reported a failure.
    const { chat } = echoingChat();

    const out = await makeReportNode(deps(chat))(
      baseState({
        analyzers: [
          { analyzer: "onchain", outcome: "ok" },
          { analyzer: "static", outcome: "ok" },
          { analyzer: "heuristic", outcome: "ok" },
          // "cua" never reported — not listed as failed, just missing.
        ],
      }),
    );

    expect(out.report).not.toBe("REPORT BODY");
    expect(out.report).toContain("Incomplete assessment");
  });
});

describe("fallbackReport: what a caller sees when synthesis itself fails", () => {
  it("still reports the deterministic severity table and finding ids", () => {
    const findings = [finding({ vulnClass: "narrowing cast" })];
    const text = fallbackReport({
      target: "some-program",
      summaryTable: "| Severity | Count |\n| --- | --- |\n| High | 1 |",
      statusTable: "(status)",
      sourceTable: "(sources)",
      findings,
      coverage: ["unsafe-type-cast"],
      error: "model timed out",
    });

    expect(text).toContain("ARES-001");
    expect(text).toContain("narrowing cast");
    expect(text).toContain("model timed out");
    // Must say synthesis failed, not just fail silently into a plain report
    // indistinguishable from a normal one.
    expect(text).toMatch(/without narrative synthesis/);
  });

  it("says explicitly that nothing survived verification, rather than leaving the section blank", () => {
    const text = fallbackReport({
      target: "some-program",
      summaryTable: "(table)",
      statusTable: "(status)",
      sourceTable: "(sources)",
      findings: [],
      coverage: [],
      error: "model timed out",
    });

    expect(text).toContain("No findings survived verification");
  });

  it("labels coverage as self-reported here too, not just in the LLM-synthesized path", () => {
    const text = fallbackReport({
      target: "x",
      summaryTable: "(table)",
      statusTable: "(status)",
      sourceTable: "(sources)",
      findings: [],
      coverage: ["missing-signer-check"],
      error: "e",
    });

    expect(text).toMatch(/self-reported/);
    expect(text).not.toMatch(/independently measured/i.test(text) ? /^$/ : /measured or verified figure it has never been/);
    expect(text).toContain("not an independently measured or verified figure");
  });
});

describe("report node: chat failure is not caught here", () => {
  it("propagates a synthesis error rather than silently returning a partial report", async () => {
    // Documented in report.ts's own comment: a throw here parks the run so
    // resuming costs one call. Swallowing it here would contradict that and
    // make failures invisible to whatever calls this node.
    await expect(
      makeReportNode(deps(throwingChat("rate limited")))(baseState()),
    ).rejects.toThrow("rate limited");
  });
});
