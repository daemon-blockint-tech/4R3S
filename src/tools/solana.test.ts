import { describe, it, expect } from "vitest";

import { loadProgram } from "./solana.js";

describe("loadProgram", () => {
  it("returns an error result for an invalid address without throwing", async () => {
    const info = await loadProgram("not-a-valid-base58-pubkey!!!");
    expect(info.exists).toBe(false);
    expect(info.executable).toBe(false);
    expect(info.error).toBe("invalid address");
    expect(info.address).toBe("not-a-valid-base58-pubkey!!!");
  });

  it("rejects an empty address as invalid (no network call)", async () => {
    const info = await loadProgram("");
    expect(info.exists).toBe(false);
    expect(info.error).toBe("invalid address");
  });
});
