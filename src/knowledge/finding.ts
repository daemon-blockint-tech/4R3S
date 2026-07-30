/**
 * The vocabulary of an audit finding.
 *
 * This lives in `knowledge/` rather than `graph/` because it is domain
 * vocabulary, not orchestration state: the vulnerability catalog and the
 * severity methodology are written in these terms and have nothing to do with
 * LangGraph. Keeping them here means `knowledge/` no longer has to import from
 * `graph/state.ts` — a dependency that pointed the wrong way and made the
 * taxonomy unusable outside the graph.
 *
 * `graph/state.ts` re-exports these so existing imports keep working.
 */

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "high" | "medium" | "low";
/** Verdict from the VERIFY phase. Undefined until a finding has been reviewed. */
export type FindingStatus = "confirmed" | "suspected" | "false-positive";

/** Severity ordering for ranking (higher = more severe). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** A single audit finding produced by an analyzer. */
export interface Finding {
  /** Vulnerability class, e.g. "signer-missing", "owner-check-bypass". */
  vulnClass: string;
  /** Instruction / account / file:line the finding concerns. */
  location: string;
  severity: Severity;
  /** Concrete evidence (tool output, code excerpt) supporting the finding. */
  evidence: string;
  /** Proposed remediation. */
  remediation: string;
  /** Which analyzer produced it. */
  source: "onchain" | "static" | "heuristic" | "cua";
  /** Catalog vulnerability id (from VULN_CATALOG), or "other". */
  category: string;
  /** True when the finding is pattern-based without code-level evidence. */
  speculative: boolean;
  /** Confidence level: high (tool/code evidence), medium (partial), low (speculative). */
  confidence: Confidence;
  /** VERIFY verdict. Undefined on freshly-produced (unverified) findings. */
  status?: FindingStatus;
  /**
   * Derived by code from tool output, with no model in the path — an on-chain
   * account field decoded from RPC bytes, not a model's reading of it. VERIFY
   * may confirm these, because re-deriving them does not mean asking the model
   * whether it believes itself. Never set from LLM output.
   */
  deterministic?: boolean;
}

/** The analyzers that can contribute findings. */
export type AnalyzerName = Finding["source"];
