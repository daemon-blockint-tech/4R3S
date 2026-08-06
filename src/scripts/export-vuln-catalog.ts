/**
 * Export VULN_CATALOG to a checked-in JSON file consumed by the Rust engine
 * at compile time (`ares-core`'s `include_str!`, ENG-2). Run this after any
 * edit to solana-vulns.ts; `solana-vulns.test.ts` fails if the two drift.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { VULN_CATALOG } from "../knowledge/solana-vulns.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_PATH = join(HERE, "..", "knowledge", "vuln-catalog.generated.json");

writeFileSync(OUT_PATH, JSON.stringify(VULN_CATALOG, null, 2) + "\n");
console.log(`wrote ${VULN_CATALOG.length} catalog entries to ${OUT_PATH}`);
