/**
 * Graph node helpers for talking to the chat model.
 */
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { HumanMessage, SystemMessage } from "@langchain/core/messages";

import { logger } from "../config/logger.js";
import { env } from "../config/env.js";
import { messageText } from "../llm/message-text.js";
import { withRetry } from "../llm/retry.js";
import { isVulnId, getVuln } from "../knowledge/solana-vulns.js";
import { citesLoadedFile, type LoadedSource } from "../tools/source.js";
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

/** Markers delimiting attacker-reachable text inside a prompt. */
export const FENCE_OPEN = "<<<BEGIN UNTRUSTED DATA>>>";
export const FENCE_CLOSE = "<<<END UNTRUSTED DATA>>>";

/**
 * Wrap attacker-reachable text so a model can tell data from instructions.
 *
 * `asData` is the wrong tool for a payload with structure — it collapses
 * whitespace, which destroys a browser transcript or a code excerpt. This keeps
 * the shape and instead does the two things that matter for a fence: it removes
 * any text that looks like a fence marker, so the payload cannot close its own
 * fence and continue as if it were the operator speaking, and it bounds the
 * length, so a hostile page cannot exhaust the context window.
 *
 * The fence is a boundary marker, not a sanitizer. It cannot stop a model from
 * being persuaded by prose inside it; what it removes is the cheap structural
 * trick, and it gives the system prompt something concrete to refer to.
 */
export function fenceUntrusted(text: string, max = 20_000): string {
  const stripped = text
    // Any BEGIN/END sentinel in the payload, however spaced or cased.
    .replace(/<{2,}\s*(?:BEGIN|END)[^>]*>{2,}/gi, "[fence marker removed]")
    .slice(0, max);
  const truncated = text.length > max ? "\n[truncated at fence budget]" : "";
  return [FENCE_OPEN, stripped + truncated, FENCE_CLOSE].join("\n");
}

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
 * silently. `downgradeSpeculative` uses `info` as a deliberate sentinel, so the
 * accident was indistinguishable from an intentional downgrade in both the logs
 * and the report, and MERGE then sorted the finding last.
 *
 * Now: trim, take the leading word, try the scale, then synonyms. Anything left
 * unresolved falls back to the catalog's `defaultSeverity` for the finding's
 * category (never below `medium` when the category is unknown) and logs. Note
 * the siblings in this same function already fail safe — `confidence` falls
 * back to the middle value and `coerceVerdicts` drops an invalid status rather
 * than defaulting it; only severity failed downward.
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
      const rawCategory = String(f.category ?? "");
      const category = isVulnId(rawCategory) ? rawCategory : "other";
      const conf = String(f.confidence ?? "").toLowerCase();
      return {
        vulnClass: asData(String(f.vulnClass ?? f.vuln_class ?? "unknown")),
        location: asData(String(f.location ?? "")),
        severity: resolveSeverity(f.severity, category),
        evidence: asData(String(f.evidence ?? ""), EVIDENCE_MAX),
        remediation: asData(String(f.remediation ?? ""), EVIDENCE_MAX),
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
/**
 * Whether `confirmed` can mean anything for this finding.
 *
 * VERIFY is handed each finding's own `evidence` string and nothing else, so
 * for `heuristic` / `onchain` / `cua` it is rating the plausibility of prose the
 * same model wrote a superstep earlier — self-certification. `confirmed` is
 * therefore allowed only where something mechanical, outside the model, backs
 * the finding:
 *
 *   - `static`, whose evidence is Semgrep's own output; or
 *   - any finding whose `location` was checked against the files actually
 *     loaded off disk (`citesLoadedFile`). That check is code, not opinion: it
 *     fails a finding that points at a file nobody read.
 *
 * A finding already flagged speculative qualifies under neither.
 *
 * This matters beyond the label. REMEMBER persists only `confirmed`,
 * non-speculative findings into durable memory that later audits recall as
 * prior knowledge — so an unearned `confirmed` is how a fabrication becomes a
 * fact the system believes about itself, while an over-strict rule would leave
 * durable memory permanently empty on any host without Semgrep.
 */
function canBeConfirmed(f: Finding, source?: LoadedSource): boolean {
  if (f.speculative) return false;
  if (f.source === "static") return true;
  // Decoded from RPC bytes by code, not authored by a model, so confirming it is
  // not self-certification. `coerceFindings` never sets this, so no model output
  // can reach it.
  if (f.deterministic) return true;
  return Boolean(source?.available) && citesLoadedFile(f.location, source!);
}

export function applyVerdicts(
  findings: Finding[],
  verdicts: Verdict[],
  source?: LoadedSource,
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
    // verbatim. Refuse it where the critic had no artifact to check it against:
    // a demotion to `suspected` costs nothing, whereas a fabricated finding
    // shipped as `confirmed` is the failure this pass exists to prevent.
    let status = v?.status ?? "suspected";
    if (status === "confirmed" && !canBeConfirmed(f, source)) {
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
  // The deadline lives here, not in the client constructor.
  //
  // `ChatOpenAI` accepts a constructor `timeout`; `ChatOpenRouter` does not —
  // it takes a per-request `AbortSignal`. Passing one here gives BOTH clients
  // the same guarantee, and it is the guarantee `withRetry` depends on: without
  // a deadline a stalled connection never produces an error, so the retry
  // wrapper has nothing to react to and the audit hangs rather than failing.
  //
  // A fresh signal per attempt, deliberately: reusing one would leave every
  // retry after the first pre-aborted.
  const res = await withRetry(
    () =>
      chat.invoke([new SystemMessage(system), new HumanMessage(human)], {
        signal: AbortSignal.timeout(env.OPENROUTER_TIMEOUT_MS),
      }),
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
