/**
 * Flatten a LangChain message's `content` (string, or array of content parts)
 * into a plain string. Shared by graph nodes and tools that need to read an
 * LLM's final text response.
 */
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
