/**
 * Independent oracle for SVC-4's PDA derivation and Merkle tree.
 *
 * `services/evidence` derives Solana PDAs with pure-stdlib Python: sha256 plus a
 * hand-rolled ed25519 on-curve test written from RFC 8032. Hand-rolled curve
 * arithmetic is exactly the kind of thing that is subtly wrong and still passes
 * its own author's tests, so this file checks it against
 * `PublicKey.findProgramAddressSync` from `@solana/web3.js` -- an implementation
 * nobody in this repository wrote.
 *
 * It also re-implements the RFC 6962 tree a third time, in a third language, and
 * checks it against the same shared vectors the Python suite and the Rust spec
 * crate assert against. Nothing may be added to the `core/` cargo workspace, so
 * that shared file is the only mechanism available for proving the three
 * implementations agree.
 *
 * Costs nothing to run: `@solana/web3.js` is already a root dependency, and
 * `vitest.config.ts` already globs `scripts/**\/*.test.ts` -- which that file's
 * own comment justifies on the grounds that a gate which greps for the wrong
 * string still exits 0.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { PublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";

const VECTORS_DIR = path.join(__dirname, "..", "services", "evidence", "vectors");

function readVectors<T>(name: string): T {
  return JSON.parse(readFileSync(path.join(VECTORS_DIR, name), "utf8")) as T;
}

// --- the shared vector shapes -------------------------------------------------

interface PdaCase {
  label: string;
  program_id_base58: string;
  authority_base58: string;
  commitment_hex: string;
  expected_pda_base58: string;
  expected_bump: number;
}

interface PdaVectors {
  seed_prefix_utf8: string;
  cases: PdaCase[];
}

interface MerkleVectors {
  algorithm: {
    domain: string;
    leaf_prefix: string;
    node_prefix: string;
  };
  leaf_payloads: string[];
  empty_root: string;
  leaf_hashes: Record<string, string>;
  roots_by_leaf_count: Record<string, string>;
  inclusion_proofs_n5: Array<{
    index: number;
    leaf_payload: string;
    proof: Array<{ position: "left" | "right"; hash: string }>;
  }>;
  malleability_check: { abc_root: string; abcc_root: string };
}

// --- a third RFC 6962 implementation ----------------------------------------

const merkleVectors = readVectors<MerkleVectors>("merkle_vectors.json");
const DOMAIN = Buffer.from(merkleVectors.algorithm.domain, "utf8");
const LEAF_PREFIX = Buffer.from(merkleVectors.algorithm.leaf_prefix, "hex");
const NODE_PREFIX = Buffer.from(merkleVectors.algorithm.node_prefix, "hex");

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function leafHash(payload: Buffer): Buffer {
  return sha256(Buffer.concat([LEAF_PREFIX, DOMAIN, payload]));
}

function nodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([NODE_PREFIX, DOMAIN, left, right]));
}

/** RFC 6962 section 2.1, transcribed. k is the largest power of two BELOW n. */
function root(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return sha256(Buffer.alloc(0));
  if (leaves.length === 1) return leafHash(leaves[0]);
  let k = 1;
  while (k * 2 < leaves.length) k *= 2;
  return nodeHash(root(leaves.slice(0, k)), root(leaves.slice(k)));
}

function payloads(n: number): Buffer[] {
  return Array.from({ length: n }, (_, i) => Buffer.from(`leaf-${i}`, "utf8"));
}

describe("SVC-4 Merkle tree, third independent implementation", () => {
  it("agrees on the empty root", () => {
    expect(root([]).toString("hex")).toBe(merkleVectors.empty_root);
  });

  it("agrees on every leaf hash", () => {
    for (const [payload, expected] of Object.entries(merkleVectors.leaf_hashes)) {
      expect(leafHash(Buffer.from(payload, "utf8")).toString("hex")).toBe(expected);
    }
  });

  it("agrees on the root for every published leaf count", () => {
    for (const [count, expected] of Object.entries(merkleVectors.roots_by_leaf_count)) {
      expect(root(payloads(Number(count))).toString("hex")).toBe(expected);
    }
  });

  it("agrees that duplicate-last does not collide (CVE-2012-2459)", () => {
    // Under the Bitcoin construction these two roots are EQUAL, which for an
    // evidence anchor would mean one root attesting to a finding set that was
    // never produced.
    const three = payloads(3);
    const fourWithDuplicate = [...three, three[2]];
    const abc = root(three).toString("hex");
    const abcc = root(fourWithDuplicate).toString("hex");

    expect(abc).not.toBe(abcc);
    expect(abc).toBe(merkleVectors.malleability_check.abc_root);
    expect(abcc).toBe(merkleVectors.malleability_check.abcc_root);
  });

  it("agrees on every inclusion proof at n=5, and each one verifies", () => {
    const leaves = payloads(5);
    const expectedRoot = root(leaves);

    for (const entry of merkleVectors.inclusion_proofs_n5) {
      let acc = leafHash(leaves[entry.index]);
      for (const step of entry.proof) {
        const sibling = Buffer.from(step.hash, "hex");
        acc = step.position === "left" ? nodeHash(sibling, acc) : nodeHash(acc, sibling);
      }
      expect(acc.toString("hex")).toBe(expectedRoot.toString("hex"));
    }
  });

  it("distinguishes a leaf from an internal node over the same bytes", () => {
    // The second-preimage property the 0x00/0x01 prefixes exist for.
    const left = Buffer.alloc(32, 7);
    const right = Buffer.alloc(32, 9);
    expect(leafHash(Buffer.concat([left, right])).toString("hex")).not.toBe(
      nodeHash(left, right).toString("hex"),
    );
  });
});

describe("SVC-4 PDA derivation, checked against @solana/web3.js", () => {
  const pdaVectors = readVectors<PdaVectors>("pda_vectors.json");
  const seedPrefix = Buffer.from(pdaVectors.seed_prefix_utf8, "utf8");

  it("has vectors to check", () => {
    // Guards against a renamed or emptied vector file making every assertion
    // below vacuous.
    expect(pdaVectors.cases.length).toBeGreaterThanOrEqual(5);
    expect(seedPrefix).toHaveLength(16);
  });

  it.each(pdaVectors.cases.map((c) => [c.label, c] as const))(
    "matches web3.js for case %s",
    (_label, testCase) => {
      const programId = new PublicKey(testCase.program_id_base58);
      const authority = new PublicKey(testCase.authority_base58);
      const commitment = Buffer.from(testCase.commitment_hex, "hex");

      const [derived, bump] = PublicKey.findProgramAddressSync(
        [seedPrefix, authority.toBuffer(), commitment],
        programId,
      );

      expect(derived.toBase58()).toBe(testCase.expected_pda_base58);
      expect(bump).toBe(testCase.expected_bump);
    },
  );

  it("covers at least one case where the on-curve rejection fires", () => {
    // A bump below 255 means the first candidate hashed to a valid ed25519 point
    // and was rejected. Without such a case the vectors would pass even if the
    // on-curve test always returned false, which is the whole thing being checked.
    const bumps = pdaVectors.cases.map((c) => c.expected_bump);
    expect(Math.min(...bumps)).toBeLessThan(255);
  });

  it("derives the seed prefix the program source declares", () => {
    const programSource = readFileSync(
      path.join(
        __dirname,
        "..",
        "services",
        "evidence",
        "onchain",
        "anchor",
        "programs",
        "evidence_registry",
        "src",
        "lib.rs",
      ),
      "utf8",
    );
    // The Rust side declares it in onchain/spec/src/seeds.rs and the program
    // references it by name; this checks the vectors were not generated against
    // some other prefix.
    expect(programSource).toContain("seeds::SEED_PREFIX");
    const specSource = readFileSync(
      path.join(__dirname, "..", "services", "evidence", "onchain", "spec", "src", "seeds.rs"),
      "utf8",
    );
    expect(specSource).toContain(`b"${pdaVectors.seed_prefix_utf8}"`);
  });
});
