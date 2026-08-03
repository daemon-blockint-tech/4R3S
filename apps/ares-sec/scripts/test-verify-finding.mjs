#!/usr/bin/env node
/**
 * test-verify-finding — proves the verification gate's teeth, especially the
 * deterministic anti-hallucination check: a finding that cites code which isn't
 * in the repo must FAIL anchor verification (→ REJECT), and a mis-cited line must
 * be caught as "present but at line N". No network needed.
 */
import fs from 'node:fs';
import path from 'node:path';
import { checkAnchors, classObligation, manualUrls, locateRepo, POC_RANK,
         checkPocArtifact, checkRefutation, checkNoveltyAttestation, checkHeadStillVulnerable,
         checkDominatingGuard, checkSeverityEvidence } from './verify-finding.mjs';

let pass = 0, fail = 0;
const ok = (label, cond, detail) =>
  (cond ? (pass++, console.log(`  ✅ ${label}${detail ? ` — ${detail}` : ''}`))
        : (fail++, console.log(`  ❌ ${label}${detail ? ` — ${detail}` : ''}`)));

// ── fixture repo ──
const FIX = '/tmp/ares-verify-fixture';
fs.mkdirSync(path.join(FIX, 'src'), { recursive: true });
fs.writeFileSync(path.join(FIX, 'src', 'driver.c'),
  ['// line1', 'void f() {', '  size_t len = answer.size();', '  memcpy(&dst, &answer[0], len);  // the sink', '}', ''].join('\n'));

console.log('\n════════ verify-finding tests ════════\n');

console.log('anchor verification (deterministic anti-hallucination)');
// real anchor at the right line → pass
let a = checkAnchors({ anchors: [{ file: 'src/driver.c', line: 4, must_contain: 'memcpy(&dst, &answer[0], len)' }] }, FIX);
ok('real snippet at cited line → allPass', a.allPass === true, a.results[0]?.note);

// snippet present but WRONG line → caught, not allPass
a = checkAnchors({ anchors: [{ file: 'src/driver.c', line: 99, must_contain: 'memcpy(&dst, &answer[0], len)' }] }, FIX);
ok('mis-cited line → flagged "present but at line N"', a.allPass === false && /present but at line 4/.test(a.results[0].note), a.results[0]?.note);

// snippet that does NOT exist → REJECT-worthy (hallucination)
a = checkAnchors({ anchors: [{ file: 'src/driver.c', line: 4, must_contain: 'strcpy(dst, evil_payload_that_is_not_here)' }] }, FIX);
ok('hallucinated snippet → allPass false', a.allPass === false && /NOT found/.test(a.results[0].note), a.results[0]?.note);

// file that does not exist → fail
a = checkAnchors({ anchors: [{ file: 'src/nope.c', line: 1, must_contain: 'x' }] }, FIX);
ok('missing file → allPass false', a.allPass === false && /file not found/.test(a.results[0].note));

// no anchors declared → missing flag
a = checkAnchors({ anchors: [] }, FIX);
ok('no anchors → missing=true', a.missing === true);

// no repo → noRepo flag
a = checkAnchors({ anchors: [{ file: 'x', line: 1, must_contain: 'y' }] }, null);
ok('no repo located → noRepo=true', a.noRepo === true);

console.log('\nclass obligation (OOB-write must state the 3 things)');
const incomplete = classObligation({ cwe: 'CWE-787', vuln_class: 'oob write', summary: 'overflow', root_cause: 'it overflows', impact: 'bad' });
ok('vague OOB-write → gaps reported', incomplete && incomplete.gaps.length >= 1, incomplete?.gaps.join('; '));
const complete = classObligation({
  cwe: 'CWE-787', vuln_class: 'oob write', summary: 'overflow',
  root_cause: 'device-controlled length memcpy into a fixed 6-byte destination buffer with no bound check', impact: 'corruption',
});
ok('complete OOB-write → no gaps', complete && complete.gaps.length === 0, `gaps: ${complete?.gaps.length}`);
const notMem = classObligation({ cwe: 'CWE-400', vuln_class: 'resource exhaustion', summary: 'oom' });
ok('non-memory class → obligation N/A', notMem === null);

console.log('\nevidence ladder + helpers');
ok('ladder orders source-verified < poc-executed', POC_RANK['source-verified'] < POC_RANK['poc-executed']);
ok('ladder: claimed is lowest', POC_RANK['claimed'] === 0);
const urls = manualUrls({ repo_url: 'https://github.com/openpgpjs/openpgpjs', package_name: 'openpgp', project: 'openpgp' });
ok('manual URLs include GH issues + OSV', urls.some(u => /issues\?q=/.test(u)) && urls.some(u => /osv\.dev/.test(u)));
ok('locateRepo honors explicit repo_path', locateRepo({ repo_path: FIX }, undefined) === FIX);

console.log('\nPoC-artifact binding (poc-executed must prove itself, not just claim)');
fs.mkdirSync(path.join(FIX, 'poc'), { recursive: true });
fs.writeFileSync(path.join(FIX, 'poc', 'x.txt'), 'harness');
let pa = checkPocArtifact({ poc_artifact: { dir: 'poc', expect_signature: 'stack-buffer-overflow', observed: 'ERROR: AddressSanitizer: stack-buffer-overflow WRITE of size 64' } }, FIX);
ok('artifact present + signature in captured output → ok', pa.ok === true, pa.notes.join('; '));
pa = checkPocArtifact({ poc_artifact: { dir: 'poc', expect_signature: 'stack-buffer-overflow', observed: 'ran fine, no crash' } }, FIX);
ok('observed lacks the signature → NOT ok (evidence does not show the bug)', pa.ok === false && pa.notes.some((n) => /does NOT contain/.test(n)));
pa = checkPocArtifact({ poc_artifact: { dir: 'does-not-exist', expect_signature: 's', observed: 's' } }, FIX);
ok('artifact path missing → NOT ok', pa.ok === false && pa.notes.some((n) => /not found/.test(n)));
pa = checkPocArtifact({}, FIX);
ok('no poc_artifact block → present=false', pa.present === false);

console.log('\nrefutation gate (anti-false-positive)');
ok('short/empty refutation → not present', checkRefutation({ refutation: 'nope' }).present === false);
ok('substantive refutation → present', checkRefutation({ refutation: 'Checked for an upstream size cap; none exists, so len>sizeof(dest) is reachable and the bug holds.' }).present === true);
ok('accepts refutation_attempted alias', checkRefutation({ refutation_attempted: 'x'.repeat(50) }).present === true);

console.log('\nnovelty attestation (dup hygiene — "already repeated")');
ok('no novelty_checked block → not present', checkNoveltyAttestation({}).present === false);
ok('fresh dated block → present, not stale', (() => { const r = checkNoveltyAttestation({ novelty_checked: { date: '2026-06-01' } }, 30, '2026-06-07'); return r.present === true && r.stale === false; })());
ok('old dated block → flagged stale', (() => { const r = checkNoveltyAttestation({ novelty_checked: { date: '2026-01-01' } }, 30, '2026-06-07'); return r.present === true && r.stale === true; })());

console.log('\nstill-vulnerable-at-HEAD (offline skip is graceful)');
ok('--no-net → head check skipped, never throws', (await checkHeadStillVulnerable({ repo_url: 'https://github.com/x/y', anchors: [{ file: 'a', must_contain: 'b' }] }, true)).skipped !== undefined);

console.log('\ndominating-guard / reachability scan (the #1 false-positive killer)');
// fixture: one GUARDED sink (function-top bound check) and one genuinely UNBOUNDED sink
fs.writeFileSync(path.join(FIX, 'src', 'parse.c'),
  ['void guarded(packet p, uint8_t* dst) {',          // 1
   '  uint16_t n = read_u16(p);',                       // 2
   '  if (n > sizeof(dst_buf)) return;   // dominating guard', // 3
   '  memcpy(dst, p.data, n);   // sink (guarded)',     // 4
   '}',                                                 // 5
   'void unbounded(packet p, uint8_t* dst) {',          // 6
   '  uint16_t m = read_u16(p);',                        // 7
   '  memcpy(dst, p.data, m);   // sink (NO guard on m)',// 8
   '}', ''].join('\n'));
let g = checkDominatingGuard({ cwe: 'CWE-787', sink: { file: 'src/parse.c', line: 4, length_var: 'n' } }, FIX);
ok('guarded sink → flags an upstream bound-check on the length var', g.applicable && g.declared && g.dominatingCandidates.length >= 1, g.dominatingCandidates.map((x) => 'L' + x.line).join(','));
g = checkDominatingGuard({ cwe: 'CWE-787', sink: { file: 'src/parse.c', line: 8, length_var: 'm' } }, FIX);
ok('unbounded sink → no dominating guard (does not false-flag a real bug)', g.applicable && g.declared && g.dominatingCandidates.length === 0);
g = checkDominatingGuard({ cwe: 'CWE-400', vuln_class: 'resource exhaustion', summary: 'oom' }, FIX);
ok('non-memory class → guard scan N/A', g.applicable === false);
g = checkDominatingGuard({ cwe: 'CWE-787', vuln_class: 'oob write', summary: 'overflow' }, FIX);
ok('memory class without sink declared → flagged as not-machine-checkable', g.applicable === true && g.declared === false);

console.log('\nseverity-evidence (CVSS vector must be backed by the reachability text)');
ok('AV:N + serial-only/adjacent → nudges toward AV:A', checkSeverityEvidence({ cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', reachability: 'attacker on the serial link / a MITM on the device cable', summary: 'x', impact: 'y' }).flags.some((x) => /AV:A/.test(x)));
ok('AC:L + non-default config → nudges toward AC:H', checkSeverityEvidence({ cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', reachability: 'a network attacker over UDP; exploitable only if the user configures an under-sized buffer; requires a non-default config' }).flags.some((x) => /AC:H/.test(x)));
ok('honest AV:N network finding → no flags', checkSeverityEvidence({ cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', reachability: 'unauthenticated UDP datagram from any source to the listening socket; a network attacker' }).flags.length === 0);
ok('no cvss vector → not applicable', checkSeverityEvidence({}).applicable === false);

console.log(`\n════════ ${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass} passed, ${fail} failed ════════\n`);
process.exit(fail === 0 ? 0 : 1);
