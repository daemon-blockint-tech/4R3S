/**
 * Graph node helpers for talking to the chat model.
 */
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { HumanMessage, SystemMessage } from "@langchain/core/messages";

import { logger } from "../config/logger.js";
import { messageText } from "../llm/message-text.js";
import { withRetry } from "../llm/retry.js";
import { isVulnId, getVuln } from "../knowledge/solana-vulns.js";
import {
  type Finding,
  type Severity,
  type Confidence,
  type FindingStatus,
  SEVERITY_RANK,
} from "./state.js";

export { messageText };

const VALID_SEVERITY = new Set(Object.keys(SEVERITY_RANK));
const VALID_CONFIDENCE = new Set(["high", "medium", "low"] as Confidence[]);
const VALID_STATUS = new Set([
  "confirmed",
  "suspected",
  "false-positive",
] as FindingStatus[]);

/** Words models reach for that aren't on our scale, mapped to the closest level. */
const SEVERITY_SYNONYMS: Record<string, Severity> = {
  severe: "critical",
  crit: "critical",
  blocker: "critical",
  major: "high",
  moderate: "medium",
  med: "medium",
  minor: "low",
  informational: "info",
  information: "info",
  note: "info",
  none: "info",
};

/**
 * Resolve a model-supplied severity onto the scale.
 *
 * The previous behaviour — membership check, else `info` — failed open in the
 * one direction an auditor must never fail: `"Critical — drains the vault"` and
 * even `"high "` with a trailing space both collapsed to the *lowest* level,
 * silently, and `downgradeSpeculative` uses `info` as a deliberate sentinel so
 * the accident was indistinguishable from an intentional downgrade.
 *
 * Now: trim, take the leading word, try the scale, then synonyms. Anything left
 * unresolved falls back to the catalog's `defaultSeverity` for the finding's
 * category (never below `medium` when the category is unknown) and logs, so a
 * mangled severity can no longer quietly disappear from the report's top rows.
 */
export function resolveSeverity(raw: unknown, category: string): Severity {
  const text = String(raw ?? "").trim().toLowerCase();
  if (!text) return "info";

  const leading = text.split(/[^a-z]+/).filter(Boolean)[0] ?? "";
  if (VALID_SEVERITY.has(leading)) return leading as Severity;
  const synonym = SEVERITY_SYNONYMS[leading];
  if (synonym) return synonym;

  const fallback = getVuln(category)?.defaultSeverity ?? "medium";
  logger.warn(
    { component: "graph", severity: text.slice(0, 40), category, fallback },
    "Unrecognized severity from model; using catalog default rather than info",
  );
  return fallback;
}

/**
 * Coerce loosely-typed LLM output into `Finding[]`, forcing `source` and
 * validating severity. Accepts either a bare array or an object with a
 * `.findings` array (the analyzers now return `{ findings, checked }`).
 * Non-array / malformed input yields `[]`.
 */
export function coerceFindings(
  raw: unknown,
  source: Finding["source"],
): Finding[] {
  const arr = Array.isArray(raw)
    ? raw
    : (raw && typeof raw === "object" && Array.isArray((raw as Record<string, unknown>).findings))
      ? (raw as Record<string, unknown>).findings as unknown[]
      : null;
  if (!arr) return [];
  return arr
    .filter((f): f is Record<string, unknown> => Boolean(f) && typeof f === "object")
    .map((f) => {
      const rawCategory = String(f.category ?? "");
      const category = isVulnId(rawCategory) ? rawCategory : "other";
      const conf = String(f.confidence ?? "").toLowerCase();
      return {
        vulnClass: String(f.vulnClass ?? f.vuln_class ?? "unknown"),
        location: String(f.location ?? ""),
        severity: resolveSeverity(f.severity, category),
        evidence: String(f.evidence ?? ""),
        remediation: String(f.remediation ?? ""),
        source,
        category,
        speculative: Boolean(f.speculative ?? false),
        confidence: (VALID_CONFIDENCE.has(conf as Confidence) ? conf : "medium") as Confidence,
      };
    });
}

/**
 * Extract the `checked` array from an LLM response object, keeping only valid
 * catalog ids. Returns `[]` if the response has no `.checked` field.
 */
export function extractChecked(raw: unknown): string[] {
  if (!raw || typeof raw !== "object") return [];
  const checked = (raw as Record<string, unknown>).checked;
  if (!Array.isArray(checked)) return [];
  return checked.filter((id): id is string => typeof id === "string" && isVulnId(id));
}

/**
 * Tag findings as speculative with low confidence and downgrade severity to
 * `info`. Used when the audit is black-box (no source code) or the target is
 * a known canonical program where heuristic pattern-matching produces noise.
 */
export function downgradeSpeculative(findings: Finding[]): Finding[] {
  return findings.map((f) => ({
    ...f,
    speculative: true,
    confidence: "low" as Confidence,
    severity: "info" as Severity,
  }));
}

/**
 * Parse a verdict's `index`, or `undefined` if it isn't one.
 *
 * `Number()` is the wrong tool here: it maps `null`, `false`, `""` and `[]` all
 * to `0`, and `0` passes every subsequent range check. Because MERGE sorts by
 * severity descending, index 0 is always the most severe finding in the run — so
 * a verdict that merely failed to carry an index was silently bound to the worst
 * finding, and a `false-positive` verdict deleted it while the report claimed it
 * had been reviewed and rejected. Only a real integer, or a string that is
 * entirely digits, counts.
 */
function parseIndex(value: unknown): number | undefined {
  if (typeof value === "number") {
    return Number.isInteger(value) && value >= 0 ? value : undefined;
  }
  if (typeof value === "string" && /^\d+$/.test(value.trim())) {
    return Number(value.trim());
  }
  return undefined;
}

/** A single VERIFY verdict, keyed to a finding by its index. */
export interface Verdict {
  index: number;
  status: FindingStatus;
  confidence: Confidence;
  reason: string;
}

/**
 * Parse the VERIFY phase LLM response into verdicts keyed by finding index.
 * Accepts either a bare array or an object with a `.verdicts` array. Entries
 * with an out-of-range index, or an invalid status/confidence, are dropped.
 */
export function coerceVerdicts(raw: unknown, count: number): Verdict[] {
  const arr = Array.isArray(raw)
    ? raw
    : raw && typeof raw === "object" && Array.isArray((raw as Record<string, unknown>).verdicts)
      ? ((raw as Record<string, unknown>).verdicts as unknown[])
      : null;
  if (!arr) return [];
  const seen = new Set<number>();
  const out: Verdict[] = [];
  for (const v of arr) {
    if (!v || typeof v !== "object") continue;
    const o = v as Record<string, unknown>;
    const index = parseIndex(o.index);
    if (index === undefined || index >= count || seen.has(index)) {
      continue;
    }
    const status = String(o.status ?? "").toLowerCase();
    const conf = String(o.confidence ?? "").toLowerCase();
    if (!VALID_STATUS.has(status as FindingStatus)) continue;
    seen.add(index);
    out.push({
      index,
      status: status as FindingStatus,
      confidence: (VALID_CONFIDENCE.has(conf as Confidence) ? conf : "low") as Confidence,
      reason: String(o.reason ?? ""),
    });
  }
  return out;
}

/**
 * Apply VERIFY verdicts to the merged findings: set each finding's `status` and
 * `confidence`, and drop those judged `false-positive`. A finding with no
 * verdict is kept and marked `suspected` (never silently dropped). Returns the
 * surviving findings and the count dropped.
 */
/**
 * Whether a finding's evidence is an artifact VERIFY could actually have
 * checked, rather than prose the same model wrote a superstep earlier.
 *
 * VERIFY is handed each finding's own `evidence` string and nothing else, so for
 * `heuristic` / `onchain` / `cua` it is rating the plausibility of text, not
 * confirming a claim about code. Only Semgrep's output is a real artifact, and
 * only when the finding was not already flagged speculative.
 */
function canBeConfirmed(f: Finding): boolean {
  return f.source === "static" && !f.speculative;
}

export function applyVerdicts(
  findings: Finding[],
  verdicts: Verdict[],
): { kept: Finding[]; dropped: number; clamped: number } {
  const byIndex = new Map(verdicts.map((v) => [v.index, v]));
  const kept: Finding[] = [];
  let dropped = 0;
  let clamped = 0;
  findings.forEach((f, i) => {
    const v = byIndex.get(i);
    if (v?.status === "false-positive") {
      dropped += 1;
      return;
    }
    // `confirmed` is the strongest label the system emits and REPORT prints it
    // verbatim. Refuse it where the critic had no artifact to check it against —
    // a demotion to `suspected` costs nothing, whereas a fabricated finding
    // shipped as `confirmed` is the failure this pass exists to prevent.
    let status = v?.status ?? "suspected";
    if (status === "confirmed" && !canBeConfirmed(f)) {
      status = "suspected";
      clamped += 1;
    }
    kept.push({
      ...f,
      status,
      confidence: v?.confidence ?? f.confidence,
    });
  });
  return { kept, dropped, clamped };
}

/**
 * Invoke the chat model with a system + human message and return text.
 * Transient failures (429 / 5xx / dropped connections) are retried with
 * exponential backoff so a single blip doesn't abort a multi-call audit;
 * deterministic errors (4xx, auth) propagate immediately.
 */
export async function chatText(
  chat: BaseChatModel,
  system: string,
  human: string,
): Promise<string> {
  const res = await withRetry(
    () =>
      chat.invoke([new SystemMessage(system), new HumanMessage(human)]),
    { label: "chat.invoke" },
  );
  return messageText(res.content);
}

/** A JSON chat result that says whether the model's output actually parsed. */
export interface JsonResult<T> {
  value: T;
  /**
   * False when the response could not be parsed and `value` is the fallback.
   * Callers that report coverage need this: an unparseable response yields zero
   * findings, which is indistinguishable from a clean result otherwise.
   */
  parsed: boolean;
}

/**
 * Invoke the chat model expecting JSON. Strips ```json fences and parses. On
 * parse failure returns `fallback` so a malformed response never crashes a node.
 */
export async function chatJson<T>(
  chat: BaseChatModel,
  system: string,
  human: string,
  fallback: T,
): Promise<T> {
  return (await chatJsonResult(chat, system, human, fallback)).value;
}

/** As `chatJson`, but also reports whether the response parsed. */
export async function chatJsonResult<T>(
  chat: BaseChatModel,
  system: string,
  human: string,
  fallback: T,
): Promise<JsonResult<T>> {
  const text = await chatText(chat, system, human);
  const cleaned = text
    .replace(/^\s*```(?:json)?\s*/i, "")
    .replace(/\s*```\s*$/i, "")
    .trim();
  try {
    return { value: JSON.parse(cleaned) as T, parsed: true };
  } catch {
    // Attempt to salvage the first JSON object/array in the text.
    const match = cleaned.match(/[[{][\s\S]*[\]}]/);
    if (match) {
      try {
        return { value: JSON.parse(match[0]) as T, parsed: true };
      } catch {
        /* fall through */
      }
    }
    logger.warn(
      { component: "graph", preview: cleaned.slice(0, 160) },
      "LLM did not return valid JSON; using fallback",
    );
    return { value: fallback, parsed: false };
  }
}
