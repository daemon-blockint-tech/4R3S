/**
 * Tests for the heuristic analyzer's relationship to program source.
 *
 * Two layers, and both are needed:
 *
 *   "source reaches the model" asserts against the prompt actually handed to
 *   the chat model — the claim KR-4 rests on. Verified by mutation: forcing
 *   `hasSource = false` fails all three prompt assertions immediately and
 *   unambiguously.
 *
 *   "citation grounding" asserts on what the node does with the model's reply
 *   once source is in context: a finding citing a file this run read is kept
 *   at full severity, anything else is demoted rather than dropped. The same
 *   mutation fails only one of these three — the other two pass, because they
 *   assert on demotion, which a blind analyzer still performs correctly. That
 *   asymmetry is the reason the prompt-level layer exists: two thirds of the
 *   citation suite cannot distinguish "read the source and found nothing
 *   citable" from "never read the source at all".
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { FENCE_OPEN, FENCE_CLOSE } from "../util.js";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";

import { makeAnalyzeHeuristicNode } from "./analyze-heuristic.js";
import { loadSource } from "../../tools/source.js";
import { CrystallineStore } from "../../memory/crystalline-store.js";
import type { AresState } from "../state.js";

let root: string;

const SOURCE_LINE = "let small = amount as u64;";
const IDL_MARKER = "withdraw_everything";

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "ares-heuristic-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(
    join(root, "src", "withdraw.rs"),
    `pub fn withdraw(amount: u128) {\n    ${SOURCE_LINE}\n}\n`,
  );
  // An Anchor IDL alongside the Rust. KR-4 asks for ".rs + IDL in context", so
  // the IDL half needs evidence of its own — a passing Rust assertion says
  // nothing about whether the IDL was included.
  writeFileSync(
    join(root, "idl.json"),
    JSON.stringify({ version: "0.1.0", name: "vault", instructions: [{ name: IDL_MARKER }] }),
  );
});

afterAll(() => rmSync(root, { recursive: true, force: true }));

/** A chat that returns whatever findings the test dictates. */
function chatReturning(findings: unknown[]): BaseChatModel {
  return {
    async invoke() {
      return {
        content: JSON.stringify({ findings, checked: ["unsafe-type-cast"] }),
      };
    },
  } as unknown as BaseChatModel;
}

/** A chat that records the prompt it was given instead of answering it. */
function capturingChat(): { chat: BaseChatModel; prompts: string[] } {
  const prompts: string[] = [];
  const chat = {
    async invoke(messages: unknown) {
      // Serialise the whole message array: the assertion should depend on the
      // text having arrived, not on the node's argument shape.
      prompts.push(JSON.stringify(messages));
      return { content: JSON.stringify({ findings: [], checked: [] }) };
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

function stateWith(source: AresState["source"], sourcePath?: string): AresState {
  return {
    request: "audit",
    recalled: [],
    source,
    ...(sourcePath ? { sourcePath } : {}),
  } as unknown as AresState;
}

const FINDING = {
  category: "unsafe-type-cast",
  vulnClass: "narrowing cast",
  severity: "high",
  evidence: "let small = amount as u64;",
  remediation: "use try_into()",
};

describe("analyze-heuristic: source reaches the model", () => {
  it("puts the actual Rust source text in the prompt", async () => {
    const source = await loadSource(join(root, "src", "withdraw.rs"));
    const { chat, prompts } = capturingChat();

    await makeAnalyzeHeuristicNode(deps(chat))(stateWith(source));

    expect(prompts).toHaveLength(1);
    // The vulnerable line itself, not a paraphrase. If this fails, the model
    // is being asked to audit code it cannot see.
    expect(prompts[0]).toContain(SOURCE_LINE);
  });

  it("puts Anchor IDL in the prompt, not only Rust", async () => {
    const source = await loadSource(root);
    const { chat, prompts } = capturingChat();

    await makeAnalyzeHeuristicNode(deps(chat))(stateWith(source));

    expect(prompts[0]).toContain(IDL_MARKER);
  });

  it("delimits the source so the model can tell code from instructions", async () => {
    const source = await loadSource(join(root, "src", "withdraw.rs"));
    const { chat, prompts } = capturingChat();

    await makeAnalyzeHeuristicNode(deps(chat))(stateWith(source));

    // The marker moved from a bespoke `BEGIN PROGRAM SOURCE` pair to the shared
    // `fenceUntrusted` sentinel. The intent this test guards is unchanged — the
    // model must be able to tell code from instructions — but the fence is now
    // one definition used for every attacker-reachable payload (source, recalled
    // memory, CUA transcripts) rather than a marker per call site.
    expect(prompts[0]).toContain(FENCE_OPEN);
    expect(prompts[0]).toContain(FENCE_CLOSE);
  });

  it("tells the model it is blind when there is no source, instead of staying silent", async () => {
    // The dangerous regression is not "no source" — it is "no source, and the
    // prompt reads the same as when there was one". Silence is what makes a
    // model fill the gap with invented locations.
    const { chat, prompts } = capturingChat();

    await makeAnalyzeHeuristicNode(deps(chat))(
      stateWith({ available: false, files: [], discovered: [], truncated: false } as never),
    );

    expect(prompts[0]).toContain("NO SOURCE CODE IS AVAILABLE");
    expect(prompts[0]).not.toContain("BEGIN PROGRAM SOURCE");
  });

  it("reports truncation to the model rather than sending a partial view silently", async () => {
    // A budget-clipped read is not a complete one, and the model cannot know
    // the difference unless told — otherwise "checked" claims coverage of
    // classes living in files that were never sent.
    const source = await loadSource(root, { budgetChars: 40 });
    const { chat, prompts } = capturingChat();

    await makeAnalyzeHeuristicNode(deps(chat))(stateWith(source));

    if (source.truncated) {
      expect(prompts[0]).toContain("context budget");
    } else {
      // Guards against a silent pass if the budget stops truncating: this
      // assertion should then fail and prompt a revisit.
      expect(source.files.length).toBe(source.discovered.length);
    }
  });
});

describe("analyze-heuristic: citation grounding", () => {
  it("keeps a finding that cites a file the run actually read", async () => {
    const source = await loadSource(root);
    const node = makeAnalyzeHeuristicNode(
      deps(chatReturning([{ ...FINDING, location: `${join("src", "withdraw.rs")}:2` }])),
    );

    const out = await node(stateWith(source, root));

    expect(out.findings).toHaveLength(1);
    expect(out.findings![0]!.severity).toBe("high");
    expect(out.findings![0]!.speculative).toBe(false);
  });

  it("demotes a finding that cites a file the run never read", async () => {
    const source = await loadSource(root);
    // A plausible path that does not exist here — the fabrication mode that
    // dominated when no source was ever loaded into context.
    const node = makeAnalyzeHeuristicNode(
      deps(chatReturning([{ ...FINDING, location: "src/vault.rs:88" }])),
    );

    const out = await node(stateWith(source, root));

    expect(out.findings).toHaveLength(1);
    expect(out.findings![0]!.speculative).toBe(true);
    expect(out.findings![0]!.severity).toBe("info");
    expect(out.findings![0]!.confidence).toBe("low");
  });

  it("demotes everything when no source could be read", async () => {
    const source = await loadSource("/does-not-exist-xyz");
    const node = makeAnalyzeHeuristicNode(
      deps(chatReturning([{ ...FINDING, location: "src/withdraw.rs:2" }])),
    );

    const out = await node(stateWith(source, "/does-not-exist-xyz"));

    expect(out.findings![0]!.speculative).toBe(true);
    expect(out.findings![0]!.severity).toBe("info");
    // The report must be able to say the analyzer ran blind.
    expect(out.analyzers![0]!.detail).toMatch(/black-box/);
  });
});
