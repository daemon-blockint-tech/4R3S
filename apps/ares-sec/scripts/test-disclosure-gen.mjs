#!/usr/bin/env node
/**
 * test-disclosure-gen — pins the disclosure generator's two load-bearing pieces:
 *   1. CVSS:3.1 base scoring, against published reference vectors (FIRST.org examples).
 *   2. the honesty gate — fires on catchable/oversold findings, stays quiet on clean ones.
 * Exit 0 = all green.
 */
import { cvss31, honestyCheck, contactChecklist } from './disclosure-gen.mjs';

let pass = 0, fail = 0;
const eq = (label, got, want) =>
  (got === want ? (pass++, console.log(`  ✅ ${label} = ${got}`))
                : (fail++, console.log(`  ❌ ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`)));
const ok = (label, cond, detail) =>
  (cond ? (pass++, console.log(`  ✅ ${label}${detail ? ` — ${detail}` : ''}`))
        : (fail++, console.log(`  ❌ ${label}${detail ? ` — ${detail}` : ''}`)));

console.log('\n════════ disclosure-gen tests ════════\n');

// ── CVSS:3.1 base-score reference vectors (must match the official calculator) ──
console.log('CVSS:3.1 base score vs published vectors');
const V = (v) => cvss31(v).score;
eq('critical C:H/I:H/A:H (S:U)', V('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
eq('max with scope change',      V('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10.0);
eq('network info-disclosure',    V('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'), 7.5);
eq('local privesc',              V('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8);
eq('reflected-XSS shape',        V('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
// representative finding shapes
eq('example device OOB write',      V('CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'), 7.5);
eq('example library catchable DoS', V('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'), 5.3);
// severity banding
eq('band of 7.5', cvss31('CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H').severity, 'High');
eq('band of 5.3', cvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L').severity, 'Medium');

// ── honesty gate ──
console.log('\nhonesty gate');
// clean High OOB-write: no warnings
const clean = honestyCheck(
  { vuln_class: 'Out-of-bounds write from device-controlled length', summary: 'overflow', impact: 'memory corruption, RCE-grade potential', severity_self: 'High' },
  cvss31('CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'));
ok('clean High finding → no honesty warnings', clean.length === 0, `${clean.length} warnings`);

// catchable DoS → must warn (recommend issue+PR)
const dos = honestyCheck(
  { vuln_class: 'uncontrolled recursion, catchable RangeError DoS', summary: 'stack exhaustion', impact: 'availability only, catchable', severity_self: 'Medium' },
  cvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'));
ok('catchable DoS → warns', dos.some(w => /issue \+ PR|catchable|availability-only/i.test(w)), `${dos.length} warnings`);

// DoS dressed up with C:H → must warn about the vector
const oversold = honestyCheck(
  { vuln_class: 'denial of service via crash', summary: 'crash', impact: 'crash only', severity_self: 'Critical' },
  cvss31('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'));
ok('DoS-only with C:H/I:H → warns to fix vector', oversold.some(w => /availability\/DoS-only but CVSS/i.test(w)), `${oversold.length} warnings`);

// inflated self-rating (Critical vs computed Low) → must warn
const inflated = honestyCheck(
  { vuln_class: 'minor read', summary: 'x', impact: 'x', severity_self: 'Critical' },
  cvss31('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N'));
ok('inflated self-rating → warns', inflated.some(w => /bands above computed/i.test(w)), `${inflated.length} warnings`);

// ── contact discovery builds the GH advisory URL ──
console.log('\nvendor-contact discovery');
const cc = contactChecklist({ repo_url: 'https://github.com/example-org/example-sdk' });
ok('builds GH private-advisory URL', cc.includes('github.com/example-org/example-sdk/security/advisories/new'));
ok('includes CERT/CC fallback', /kb\.cert\.org/.test(cc));
ok('warns against public posting', /Do NOT post/.test(cc));

console.log(`\n════════ ${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass} passed, ${fail} failed ════════\n`);
process.exit(fail === 0 ? 0 : 1);
