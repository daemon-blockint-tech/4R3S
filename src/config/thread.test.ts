import { describe, it, expect } from "vitest";
import { resolve } from "node:path";

import { auditThreadId } from "./thread.js";

describe("auditThreadId", () => {
  it("is stable for the same target", () => {
    const a = auditThreadId({ program: "Prog111" });
    const b = auditThreadId({ program: "Prog111" });
    expect(a).toBe(b);
    expect(a).toMatch(/^ares-[0-9a-f]{16}$/);
  });

  it("separates different targets so their checkpoints never collide", () => {
    const a = auditThreadId({ program: "Prog111" });
    const b = auditThreadId({ program: "Prog222" });
    const c = auditThreadId({ source: "./prog" });
    expect(new Set([a, b, c]).size).toBe(3);
  });

  it("treats equivalent source paths as one audit", () => {
    expect(auditThreadId({ source: "./prog" })).toBe(
      auditThreadId({ source: resolve("prog") }),
    );
  });

  it("distinguishes a program-only audit from the same program plus source", () => {
    expect(auditThreadId({ program: "Prog111" })).not.toBe(
      auditThreadId({ program: "Prog111", source: "./prog" }),
    );
  });

  it("honours an explicit override and ignores surrounding whitespace", () => {
    expect(auditThreadId({ program: "Prog111", override: "pinned" })).toBe("pinned");
    expect(auditThreadId({ program: "Prog111", override: "  pinned  " })).toBe("pinned");
  });

  it("falls back to the derived id when the override is blank", () => {
    expect(auditThreadId({ program: "Prog111", override: "   " })).toBe(
      auditThreadId({ program: "Prog111" }),
    );
  });
});
