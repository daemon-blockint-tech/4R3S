import { describe, it, expect } from "vitest";

import { NEO4J_CYPHER, toLuceneQuery } from "./neo4j-retriever.js";

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

  it("drops Lucene's reserved keywords, not just its punctuation", () => {
    // "does NOT verify the owner" is how a security request is actually
    // written. Left in, the uppercase keyword lands between the ` OR ` joiners
    // ("does OR NOT OR verify"), Lucene throws a ParseException, and the whole
    // lexical graph match is reported failed for the audit.
    expect(toLuceneQuery("the withdraw handler does NOT verify the owner")).toBe(
      "the OR withdraw OR handler OR does OR verify OR the OR owner",
    );
    expect(toLuceneQuery("owner AND signer TO delegate OR mint")).toBe(
      "owner OR signer OR delegate OR mint",
    );
    // Reserved only in uppercase — the lowercase word is an ordinary term.
    expect(toLuceneQuery("does not check the signer")).toContain("not");
  });
});

/**
 * The queries cannot be executed without a live Neo4j, so pin the shape whose
 * absence is the invariant: one row per chunk. A trailing
 * `OPTIONAL MATCH (c)-[:MENTIONS]->(e:Entity)` re-fans each chunk into one row
 * per mentioned entity — up to 20 — all carrying the same id and the same
 * score, which spends `LIMIT` on copies and lets `HybridRetriever.merge` bank
 * the graph weight once per entity.
 */
describe("graph queries", () => {
  it("return one row per chunk, with no entity fan-out", () => {
    expect(NEO4J_CYPHER.search).not.toMatch(/MENTIONS/);
    expect(NEO4J_CYPHER.expand).not.toMatch(/MENTIONS/);
    // expand() aggregates its own multi-path fan-out; nothing may follow it.
    expect(NEO4J_CYPHER.expand).toMatch(/WITH n, min\(length\(path\)\) AS hops/);
    expect(NEO4J_CYPHER.expand.split("WITH n,")[1]).not.toMatch(/MATCH/);
  });
});

const LUCENE_CHARS = /[+\-&|!(){}[\]^"~*?:\\/]/;
