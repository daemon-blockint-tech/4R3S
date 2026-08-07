import { describe, it, expect, afterEach } from "vitest";

import { hasCua, setCuaOverride, runCuaInvestigation, createCuaGraph } from "./cua.js";

describe("hasCua", () => {
  afterEach(() => {
    setCuaOverride(false);
  });

  it("is false by default in the test env (no CUA/Scrapybara keys)", () => {
    expect(hasCua()).toBe(false);
  });

  it("stays false even with the runtime override when API keys are missing", () => {
    setCuaOverride(true);
    // OPENAI_API_KEY / SCRAPYBARA_API_KEY are unset in the test env, so CUA
    // must remain unavailable regardless of the enable flag.
    expect(hasCua()).toBe(false);
  });
});

describe("runCuaInvestigation", () => {
  it("returns unavailable without calling Scrapybara/OpenAI when not configured", async () => {
    const result = await runCuaInvestigation("investigate program X");
    expect(result.available).toBe(false);
    expect(result.transcript).toBe("");
    expect(result.note).toBeTruthy();
  });
});

describe("VM cleanup", () => {
  // The VM is started inside the graph, so its id lived only in graph state
  // until `invoke` returned — and `invoke` throwing is the case the cleanup
  // exists for (GraphRecursionError at CUA_RECURSION_LIMIT is ~24 browser
  // actions, not an exotic outcome). The id has to be captured while the run is
  // still alive, which means at a node, not at the return value. Driving the
  // real compiled graph's node is what shows the capture is actually wired in;
  // the surrounding leak needs a live Scrapybara VM to observe directly.
  it("reports the VM id from the node that runs right after the VM is created", async () => {
    const seen: string[] = [];
    const graph = createCuaGraph((id) => seen.push(id));

    // `createVMInstance` -> `nodeBeforeAction` is an unconditional edge, and
    // the state it hands over is the one holding the fresh instance id.
    await graph.nodes.nodeBeforeAction!.invoke(
      { instanceId: "vm-under-test", messages: [] },
      {},
    );

    expect(seen).toEqual(["vm-under-test"]);
  });
});
