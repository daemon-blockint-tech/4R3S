import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";

import { makeAnalyzeHeuristicNode } from "./analyze-heuristic.js";
import { loadSource } from "../../tools/source.js";
import { CrystallineStore } from "../../memory/crystalline-store.js";
import type { AresState } from "../state.js";

let root: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "ares-heuristic-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(
    join(root, "src", "withdraw.rs"),
    "pub fn withdraw(amount: u128) {\n    let small = amount as u64;\n}\n",
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

function deps(chat: BaseChatModel) {
  return {
    chat,
    crystalline: new CrystallineStore(),
    retriever: { retrieve: async () => [] } as never,
  };
}

const FINDING = {
  category: "unsafe-type-cast",
  vulnClass: "narrowing cast",
  severity: "high",
  evidence: "let small = amount as u64;",
  remediation: "use try_into()",
};

describe("analyze-heuristic citation grounding", () => {
  it("keeps a finding that cites a file the run actually read", async () => {
    const source = await loadSource(root);
    const node = makeAnalyzeHeuristicNode(
      deps(chatReturning([{ ...FINDING, location: `${join("src", "withdraw.rs")}:2` }])),
    );

    const out = await node({ request: "audit", sourcePath: root, source, recalled: [] } as unknown as AresState);

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

    const out = await node({ request: "audit", sourcePath: root, source, recalled: [] } as unknown as AresState);

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

    const out = await node({
      request: "audit",
      sourcePath: "/does-not-exist-xyz",
      source,
      recalled: [],
    } as unknown as AresState);

    expect(out.findings![0]!.speculative).toBe(true);
    expect(out.findings![0]!.severity).toBe("info");
    // The report must be able to say the analyzer ran blind.
    expect(out.analyzers![0]!.detail).toMatch(/black-box/);
  });
});
