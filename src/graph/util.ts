/**
 * Graph node helpers for talking to the chat model.
 */
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { HumanMessage, SystemMessage } from "@langchain/core/messages";

import { logger } from "../config/logger.js";
import { messageText } from "../llm/message-text.js";
import { isVulnId } from "../knowledge/solana-vulns.js";
import { type Finding, type Severity, SEVERITY_RANK } from "./state.js";

export { messageText };

const VALID_SEVERITY = new Set(Object.keys(SEVERITY_RANK));

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
      const sev = String(f.severity ?? "info").toLowerCase();
      const rawCategory = String(f.category ?? "");
      return {
        vulnClass: String(f.vulnClass ?? f.vuln_class ?? "unknown"),
        location: String(f.location ?? ""),
        severity: (VALID_SEVERITY.has(sev) ? sev : "info") as Severity,
        evidence: String(f.evidence ?? ""),
        remediation: String(f.remediation ?? ""),
        source,
        category: isVulnId(rawCategory) ? rawCategory : "other",
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

/** Invoke the chat model with a system + human message and return text. */
export async function chatText(
  chat: BaseChatModel,
  system: string,
  human: string,
): Promise<string> {
  const res = await chat.invoke([
    new SystemMessage(system),
    new HumanMessage(human),
  ]);
  return messageText(res.content);
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
  const text = await chatText(chat, system, human);
  const cleaned = text
    .replace(/^\s*```(?:json)?\s*/i, "")
    .replace(/\s*```\s*$/i, "")
    .trim();
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    // Attempt to salvage the first JSON object/array in the text.
    const match = cleaned.match(/[[{][\s\S]*[\]}]/);
    if (match) {
      try {
        return JSON.parse(match[0]) as T;
      } catch {
        /* fall through */
      }
    }
    logger.warn(
      { component: "graph", preview: cleaned.slice(0, 160) },
      "LLM did not return valid JSON; using fallback",
    );
    return fallback;
  }
}
