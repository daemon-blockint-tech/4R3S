#!/usr/bin/env node
/**
 * test-disclose-pipeline — pins the SEC-4 coordinated-disclosure pipeline.
 * Fully OFFLINE and hermetic: no network, no compiler toolchain, no LLM key, no
 * built dist/ required. It exercises the pipeline end-to-end against an inline
 * finding fixture written to a temp dir, plus unit tests on the pure verdict
 * logic and a static assertion of the DRAFTS-ONLY invariant.
 *
 * What it proves:
 *   1. decideVerdict() — the gate is permissive (refuter is the only blocker),
 *      advisories are informational, exit codes are correct.
 *   2. End-to-end (drafts path): a valid finding, run with --no-net --no-poc
 *      --no-refute, yields exit 0, three draft files, and a pipeline report that
 *      records each gated stage as a reported skip (no silent skips).
 *   3. End-to-end (refuted path): a cached REFUTED refutation report blocks the
 *      drafts and exits 3 — no disclosure is written for a likely false positive.
 *   4. End-to-end (bad input): a finding missing a required field exits 2.
 *   5. DRAFTS-ONLY invariant: the orchestrator source contains no import of
 *      src/integrations/bounty, no .submit( call, and no bounty-platform host.
 * Exit 0 = all green.
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { decideVerdict } from './disclose-pipeline.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PIPELINE = path.join(HERE, 'disclose-pipeline.mjs');

let pass = 0, fail = 0;
const ok = (label, cond, detail) =>
  (cond ? (pass++, console.log(`  ✅ ${label}${detail ? ` — ${detail}` : ''}`))
        : (fail++, console.log(`  ❌ ${label}${detail ? ` — ${detail}` : ''}`)));

const run = (args) => spawnSync(process.execPath, [PIPELINE, ...args], { encoding: 'utf8' });

// A clean, honest, external-looking finding — no internal tooling names, no local
// paths, CVSS vector consistent with the class, so disclosure-gen stays quiet.
function fixture(slug) {
  return {
    slug,
    project: 'Acme Serialize',
    component: 'acme-serialize',
    ecosystem: 'npm',
    package_name: 'acme-serialize',
    repo_url: 'https://github.com/acme-labs/acme-serialize',
    versions_affected: '< 2.4.1',
    commit: '0000000000000000000000000000000000000000',
    vuln_class: 'Out-of-bounds write from attacker-controlled length',
    cwe: 'CWE-787',
    summary: 'A crafted length field drives a write past the end of a fixed buffer.',
    root_cause: 'The decode routine trusts a length taken from the input without bounding it against the destination capacity.',
    poc: 'Send a record whose declared length exceeds the destination capacity; the copy runs past the buffer.',
    impact: 'Memory corruption with potential for remote code execution.',
    remediation: 'Bound the declared length against the destination capacity before the copy.',
    cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    severity_self: 'Critical',
    reachability: 'reachable from the public decode entry point',
    sink: { file: 'src/decode.c', line: 88, length_var: 'declared_len' },
  };
}

console.log('\n════════ disclose-pipeline tests ════════\n');

// ── 1. decideVerdict — the permissive gate ──────────────────────────────────
console.log('decideVerdict (permissive gate, refuter is the only blocker)');
{
  const refuted = decideVerdict({ refuter: { status: 'refuted', blocks: true, verdict: 'REFUTED', refutedCount: 2, total: 3 } });
  ok('refuter REFUTED → verdict REFUTED, exit 3', refuted.verdict === 'REFUTED' && refuted.exit === 3);

  const drafted = decideVerdict({
    refuter: { status: 'survived', blocks: false, verdict: 'SURVIVED' },
    osv: { status: 'novel', count: 3, overlaps: [] },
    poc: { status: 'reproduced' },
    disclosure: { status: 'written', files: ['a', 'b', 'c'] },
  });
  ok('clean survived finding → DRAFTED, exit 0, no advisories', drafted.verdict === 'DRAFTED' && drafted.exit === 0 && drafted.advisories.length === 0);

  const dup = decideVerdict({
    refuter: { status: 'skipped', blocks: false, reason: 'disabled by --no-refute' },
    osv: { status: 'possible-duplicate', overlaps: ['GHSA-xxxx', 'CVE-2021-1'] },
    poc: { status: 'gated', reason: 'no clang' },
    disclosure: { status: 'written-needs-review', files: ['a'] },
  });
  ok('osv dup + poc gated + refuter skip → still DRAFTED, exit 0', dup.verdict === 'DRAFTED' && dup.exit === 0);
  ok('  ↳ advisories capture dup, poc-gated, refuter-skipped, review',
    dup.advisories.some(a => /osv-possible-duplicate/.test(a)) &&
    dup.advisories.some(a => /poc-gated/.test(a)) &&
    dup.advisories.some(a => /refuter-skipped/.test(a)) &&
    dup.advisories.some(a => /disclosure-review/.test(a)),
    `${dup.advisories.length} advisories`);

  const bad = decideVerdict({ refuter: { blocks: false }, disclosure: { status: 'bad-input' } });
  ok('disclosure bad-input → BAD-INPUT, exit 2', bad.verdict === 'BAD-INPUT' && bad.exit === 2);

  // a disclosure stage that wrote nothing must NEVER be reported as DRAFTED/exit 0
  const derr = decideVerdict({ refuter: { blocks: false }, disclosure: { status: 'error', reason: 'wrote no files' } });
  ok('disclosure wrote nothing → ERROR, exit 2 (not a silent exit-0 with 0 files)', derr.verdict === 'ERROR' && derr.exit === 2);

  // a refuter that ran but produced no verdict is surfaced, but is not a blocker
  const rerr = decideVerdict({
    refuter: { status: 'error', blocks: false, reason: 'ran but wrote no report' },
    disclosure: { status: 'written', files: ['a', 'b', 'c'] },
  });
  ok('refuter error → advisory, still DRAFTED (permissive)', rerr.verdict === 'DRAFTED' && rerr.exit === 0 && rerr.advisories.some(a => /refuter-error/.test(a)));
}

// ── 2. end-to-end: drafts path (fully offline) ──────────────────────────────
console.log('\nend-to-end · drafts path (--no-net --no-poc --no-refute)');
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec4-drafts-'));
  const fp = path.join(dir, 'finding.json');
  const f = fixture('acme-oob-write');
  fs.writeFileSync(fp, JSON.stringify(f, null, 2));

  const r = run(['--finding', fp, '--no-net', '--no-poc', '--no-refute']);
  ok('pipeline exits 0 (drafts written)', r.status === 0, `exit ${r.status}`);

  const outDir = path.join(dir, 'acme-oob-write.disclosure');
  ok('draft report written', fs.existsSync(path.join(outDir, 'disclosure-report.md')));
  ok('draft email written', fs.existsSync(path.join(outDir, 'disclosure-email.txt')));
  ok('send checklist written', fs.existsSync(path.join(outDir, 'SEND-CHECKLIST.md')));

  const repPath = path.join(dir, 'acme-oob-write.pipeline-report.json');
  ok('pipeline report written', fs.existsSync(repPath));
  if (fs.existsSync(repPath)) {
    const rep = JSON.parse(fs.readFileSync(repPath, 'utf8'));
    ok('  ↳ verdict DRAFTED', rep.verdict === 'DRAFTED');
    ok('  ↳ drafts_only flag is true', rep.drafts_only === true);
    ok('  ↳ osv reported as skipped (--no-net), not silent', rep.stages.osv.status === 'skipped' && !!rep.stages.osv.reason);
    ok('  ↳ poc reported as skipped, not silent', rep.stages.poc.status === 'skipped' && !!rep.stages.poc.reason);
    ok('  ↳ refuter reported as skipped, not silent', rep.stages.refuter.status === 'skipped' && !!rep.stages.refuter.reason);
    ok('  ↳ drafts block lists the written files', rep.drafts && rep.drafts.files.length === 3);
  }
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 3. end-to-end: refuted path blocks drafts ───────────────────────────────
console.log('\nend-to-end · refuted path (cached REFUTED report blocks drafting)');
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec4-refuted-'));
  const fp = path.join(dir, 'finding.json');
  const f = fixture('acme-refuted');
  fs.writeFileSync(fp, JSON.stringify(f, null, 2));
  // pre-seed the handshake file refute-finding would have written
  fs.writeFileSync(path.join(dir, 'acme-refuted.refutation_report.json'), JSON.stringify({
    slug: 'acme-refuted', verdict: 'REFUTED', refutedCount: 2, total: 3,
    killing_guards: [{ file: 'src/decode.c', line: 40 }], verdicts: [], at: '1970-01-01T00:00:00.000Z',
  }, null, 2));

  const r = run(['--finding', fp, '--no-net', '--no-poc']); // refuter reuses the cached report
  ok('pipeline exits 3 (refuted)', r.status === 3, `exit ${r.status}`);
  ok('no disclosure dir created for a refuted finding', !fs.existsSync(path.join(dir, 'acme-refuted.disclosure')));
  const rep = JSON.parse(fs.readFileSync(path.join(dir, 'acme-refuted.pipeline-report.json'), 'utf8'));
  ok('  ↳ verdict REFUTED, drafts null', rep.verdict === 'REFUTED' && rep.drafts === null);
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 4. end-to-end: bad input ────────────────────────────────────────────────
console.log('\nend-to-end · bad input');
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec4-bad-'));
  const fp = path.join(dir, 'finding.json');
  const f = fixture('acme-bad');
  delete f.summary; // required field
  fs.writeFileSync(fp, JSON.stringify(f, null, 2));
  const r = run(['--finding', fp, '--no-net', '--no-poc', '--no-refute']);
  ok('missing required field → exit 2', r.status === 2, `exit ${r.status}`);
  ok('  ↳ names the missing field', /summary/.test(r.stderr), r.stderr.trim().split('\n')[0]);

  const r2 = run(['--finding', path.join(dir, 'does-not-exist.json'), '--no-net']);
  ok('missing finding file → exit 2', r2.status === 2, `exit ${r2.status}`);
  fs.rmSync(dir, { recursive: true, force: true });
}

// ── 5. DRAFTS-ONLY static invariant ─────────────────────────────────────────
console.log('\ndrafts-only invariant (no submit path in the orchestrator)');
{
  const src = fs.readFileSync(PIPELINE, 'utf8');
  ok('no import of src/integrations/bounty', !/from\s+['"][^'"]*integrations\/bounty/.test(src) && !/require\(\s*['"][^'"]*bounty/.test(src));
  ok('no .submit( call', !/\.submit\s*\(/.test(src));
  ok('no bounty-platform host literal', !/api\.(hackerone|bugcrowd|intigriti)\.com/i.test(src));
  ok('invariant is documented (DRAFTS ONLY)', /DRAFTS ONLY/.test(src));
}

console.log(`\n════════ ${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass} passed, ${fail} failed ════════\n`);
process.exit(fail === 0 ? 0 : 1);
