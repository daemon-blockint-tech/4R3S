import { describe, it, expect } from "vitest";

import { toLuceneQuery } from "./neo4j-retriever.js";

/**
 * The regression these cover: the retriever matched with
 * `toLower(c.content) CONTAINS toLower($text)`, which required one chunk to
 * contain the entire query string verbatim. `$text` is `intake.summary` — a
 * whole sentence — so no corpus chunk ever matched, yet the source reported
 * `ok` with zero fragments, making "answered and had nothing" look identical to
 * "never worked". These pin the query builder that replaced it.
 */
describe("toLuceneQuery", () => {
  it("ORs the terms of a sentence so partial overlap can match", () => {
    expect(toLuceneQuery("audit the vault withdraw instruction")).toBe(
      "audit OR the OR vault OR withdraw OR instruction",
    );
  });

  it("escapes Lucene operators that appear in real audit input", () => {
    // A program address, a file path and a rule id all carry characters Lucene
    // parses as syntax; unescaped they are a query error, not a search term.
    const out = toLuceneQuery("src/lib.rs:42 rust.lang-security (missing)");
    expect(out).not.toMatch(LUCENE_CHARS);
    expect(out).toContain("srclib.rs42");
  });

  it("drops noise words too short to be worth a term", () => {
    expect(toLuceneQuery("a an is the vault")).toBe("the OR vault");
  });

  it("returns empty string when nothing usable survives", () => {
    // The caller turns this into "no fragments" rather than sending a query
    // that would match the entire corpus.
    expect(toLuceneQuery("")).toBe("");
    expect(toLuceneQuery("   ")).toBe("");
    expect(toLuceneQuery("a b c")).toBe("");
    expect(toLuceneQuery("+ - || &&")).toBe("");
  });

  it("bounds the term count so a long summary cannot build a huge query", () => {
    const long = Array.from({ length: 200 }, (_, i) => `term${i}`).join(" ");
    expect(toLuceneQuery(long).split(" OR ")).toHaveLength(24);
  });
});

const LUCENE_CHARS = /[+\-&|!(){}[\]^"~*?:\\/]/;
