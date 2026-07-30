import { describe, it, expect } from "vitest";

import {
  CSV_HEADER,
  predictionRows,
  rowToCsvLine,
  toCsv,
  type PredictionRow,
} from "./eval-predict.js";
import type { Finding } from "../knowledge/finding.js";

function finding(over: Partial<Finding> = {}): Finding {
  return {
    vulnClass: "x",
    location: "lib.rs:1",
    severity: "high",
    evidence: "e",
    remediation: "r",
    source: "heuristic",
    category: "missing-signer-check",
    speculative: false,
    confidence: "high",
    ...over,
  };
}

describe("predictionRows", () => {
  it("emits one row per finding, carrying the fields the scorer filters on", () => {
    const rows = predictionRows(
      [
        finding({ category: "missing-signer-check", status: "confirmed" }),
        finding({ category: "arbitrary-cpi", status: "suspected", confidence: "low" }),
      ],
      "prog-42",
    );
    expect(rows).toEqual<PredictionRow[]>([
      { target_id: "prog-42", category: "missing-signer-check", confidence: "high", status: "confirmed", speculative: false, severity: "high" },
      { target_id: "prog-42", category: "arbitrary-cpi", confidence: "low", status: "suspected", speculative: false, severity: "high" },
    ]);
  });

  it("does not collapse two findings of the same class — the scorer dedups after filtering", () => {
    const rows = predictionRows(
      [
        finding({ category: "arbitrary-cpi", status: "false-positive" }),
        finding({ category: "arbitrary-cpi", status: "confirmed" }),
      ],
      "t",
    );
    expect(rows.map((r) => r.status)).toEqual(["false-positive", "confirmed"]);
  });

  it("renders an unverified finding's absent status as an empty cell", () => {
    const [row] = predictionRows([finding({ status: undefined })], "t");
    expect(row!.status).toBe("");
  });
});

describe("CSV serialization", () => {
  it("empty findings yield header only", () => {
    expect(toCsv([])).toBe(CSV_HEADER + "\n");
  });

  it("quotes only fields carrying a comma, quote, or newline", () => {
    const row: PredictionRow = {
      target_id: 'weird,"id',
      category: "other",
      confidence: "medium",
      status: "",
      speculative: true,
      severity: "low",
    };
    expect(rowToCsvLine(row)).toBe('"weird,""id",other,medium,,true,low');
  });

  it("round-trips a normal row without quoting", () => {
    const [row] = predictionRows([finding({ category: "type-cosplay" })], "abc123");
    expect(rowToCsvLine(row!)).toBe("abc123,type-cosplay,high,,false,high");
  });
});
