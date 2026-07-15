/**
 * Graph node helpers for talking to the chat model.
 */
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { HumanMessage, SystemMessage } from "@langchain/core/messages";

import { logger } from "../config/logger.js";
import { type Finding, type Severity, SEVERITY_RANK } from "./state.js";

const VALID_SEVERITY = new Set(Object.keys(SEVERITY_RANK));

/**
 * Coerce loosely-typed LLM output into `Finding[]`, forcing `source` and
 * validating severity. Non-array / malformed input yields `[]`.
 */
export function coerceFindings(
  raw: unknown,
  source: Finding["source"],
): Finding[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((f): f is Record<string, unknown> => Boolean(f) && typeof f === "object")
    .map((f) => {
      const sev = String(f.severity ?? "info").toLowerCase();
      return {
        vulnClass: String(f.vulnClass ?? f.vuln_class ?? "unknown"),
        location: String(f.location ?? ""),
        severity: (VALID_SEVERITY.has(sev) ? sev : "info") as Severity,
        evidence: String(f.evidence ?? ""),
        remediation: String(f.remediation ?? ""),
        source,
      };
    });
}

/** Flatten an LLM message's content into a plain string. */
export function messageText(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .map((part) =>
        typeof part === "string"
          ? part
          : part && typeof part === "object" && "text" in part
            ? String((part as { text: unknown }).text)
            : "",
      )
      .join("");
  }
  return String(content ?? "");
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
