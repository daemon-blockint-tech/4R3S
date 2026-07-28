/**
 * Graph node helpers for talking to the chat model.
 */
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { HumanMessage, SystemMessage } from "@langchain/core/messages";

import { logger } from "../config/logger.js";
import { messageText } from "../llm/message-text.js";
import { withRetry } from "../llm/retry.js";
import { isVulnId } from "../knowledge/solana-vulns.js";
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

/**
 * Neutralize a string that originated outside the auditor before it is placed
 * in a prompt.
 *
 * Finding fields are reachable by the audited party. Semgrep lifts `path`
 * straight from the target repository — a directory name is enough — and
 * `message` from rule metavariables that interpolate matched source; the CUA
 * transcript is whatever a web page said. VERIFY is the only node that deletes
 * findings, so text that reaches its prompt is text that can argue for its own
 * dismissal.
 *
 * This strips control characters (including the newlines used to fake a
 * delimiter), neutralizes backticks, collapses whitespace and truncates. It is
 * not a parser and cannot make prose safe — the structural defence is the
 * sentinel fence in `verify.ts`. What it removes is the cheap trick, and it
 * bounds prompt growth on a hostile input at the same time.
 */
export function asData(value: string, max = 300): string {
  const cleaned = value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]+/g, " ")
    .replace(/`/g, "'")
    .replace(/\s+/g, " ")
    .trim();
  return cleaned.length > max ? `${cleaned.slice(0, max)}\u2026` : cleaned;
}

/** Evidence carries real code excerpts, so it gets a longer bound than labels. */
const EVIDENCE_MAX = 2000;

/**
 * Coerce loosely-typed LLM output into `Finding[]`, forcing `source` and
 * validating severity. Accepts either a bare array or an object with a
 * `.findings` array (the analyzers now return `{ findings, checked }`).
 * Non-array / malformed input yields `[]`.
 *
 * Free-text fields pass through `asData` — they end up in the VERIFY prompt,
 * and `category` is the only field that was ever validated.
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
      const sev = String(f.severity ?? "info").toLowerCase();
      const rawCategory = String(f.category ?? "");
      const conf = String(f.confidence ?? "").toLowerCase();
      return {
        vulnClass: asData(String(f.vulnClass ?? f.vuln_class ?? "unknown")),
        location: asData(String(f.location ?? "")),
        severity: (VALID_SEVERITY.has(sev) ? sev : "info") as Severity,
        evidence: asData(String(f.evidence ?? ""), EVIDENCE_MAX),
        remediation: asData(String(f.remediation ?? ""), EVIDENCE_MAX),
        source,
        category: isVulnId(rawCategory) ? rawCategory : "other",
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
    // `Number(o.index)` alone is unsafe: Number(null), Number(false) and
    // Number("") are all 0, and 0 passes Number.isInteger. MERGE has already
    // sorted findings by severity descending, so index 0 is the most severe
    // finding in the report — a verdict with a null or empty index would be
    // applied to it, and a "false-positive" status would delete it outright.
    // Only genuine numbers, or numeric strings, may address a finding.
    const rawIndex = o.index;
    const index =
      typeof rawIndex === "number"
        ? rawIndex
        : typeof rawIndex === "string" && rawIndex.trim() !== ""
          ? Number(rawIndex)
          : Number.NaN;
    if (!Number.isInteger(index) || index < 0 || index >= count || seen.has(index)) {
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
export function applyVerdicts(
  findings: Finding[],
  verdicts: Verdict[],
): { kept: Finding[]; dropped: number } {
  const byIndex = new Map(verdicts.map((v) => [v.index, v]));
  const kept: Finding[] = [];
  let dropped = 0;
  findings.forEach((f, i) => {
    const v = byIndex.get(i);
    if (v?.status === "false-positive") {
      dropped += 1;
      return;
    }
    kept.push({
      ...f,
      status: v?.status ?? "suspected",
      confidence: v?.confidence ?? f.confidence,
    });
  });
  return { kept, dropped };
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
