#!/usr/bin/env node
/**
 * lint-disclosure — vendor-cleanliness linter for OUTGOING disclosure artifacts.
 *
 * A disclosure report goes to an outside vendor. It must NOT carry: local
 * filesystem paths, internal scratch/clone paths, internal tooling names, the
 * "STRIP BEFORE SENDING" block, TODO/FIXME markers, unfilled reporter
 * placeholders, secrets, or the names of OTHER projects we audited (it's
 * unprofessional + leaks our pipeline to tell vendor A about vendor B). Manual
 * validation kept catching exactly these (another vendor's name in a report, /tmp
 * paths, a stale STRIP block) — this makes them fail by construction.
 *
 * Two severities: `block` (hard leak — must fix before sending) and `warn`
 * (mentions another audited project — confirm it's intentional).
 *
 * Usage:
 *   node scripts/lint-disclosure.mjs --dir bench/wild-hunt/disclosures/<slug> [--target "Vendor/Repo"]
 *   node scripts/lint-disclosure.mjs --file <report.md> [--target ...]
 *   node scripts/lint-disclosure.mjs --self-test
 * Exit 0 = clean · 3 = blocking leak(s) · 2 = bad input.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HARD = [
  [/\/(?:tmp|Users|home|private|var\/folders)\//, 'local filesystem path'],
  [/wild-recon|crit-hunt|bench\/wild-hunt|\.claude\/|\/Desktop\//, 'internal repo/scratch path'],
  [/\bares\b|\bwild-hunt\b|\bcrit-hunt\b|verify-finding|disclosure-gen|gate-precision|refute-finding|\brefuter\b/i, 'internal tooling name'],
  [/INTERNAL\s*[—-]\s*STRIP|STRIP BEFORE SENDING|<!--\s*─+\s*INTERNAL/, 'internal STRIP-before-sending block'],
  [/\bTODO\b|\bFIXME\b|\bXXX:/, 'internal TODO/FIXME marker'],
  [/\[your[- ][a-z -]*\]|<your[- ][a-z-]*>|TODO[- ]EMAIL|REPLACE[- ]ME/i, 'unfilled reporter placeholder'],
  [/\bsk-[A-Za-z0-9]{16,}\b|\bghp_[A-Za-z0-9]{20,}\b|\bAKIA[0-9A-Z]{12,}\b|-----BEGIN [A-Z ]*PRIVATE KEY-----/, 'possible secret/credential'],
];
// Other projects you have audited — mentioning them in a different vendor's report
// leaks your pipeline (vendor A learns you also looked at vendor B). Populate this
// with the OSS you audit; illustrative placeholders below.
const OTHER_PROJECTS = ['otherlib', 'examplevendor', 'thirdparty-sdk'];

function lintDisclosure(text, { target = '' } = {}) {
  const issues = [];
  const lines = String(text).split('\n');
  const targetToks = target.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length > 2);
  const isTarget = (name) => targetToks.some((tt) => name.includes(tt) || tt.includes(name));
  let inCode = false;
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    if (/^```/.test(ln.trim())) { inCode = !inCode; continue; }
    for (const [re, label] of HARD) if (re.test(ln)) issues.push({ sev: 'block', label, line: i + 1, snippet: ln.trim().slice(0, 90) });
    const low = ln.toLowerCase();
    for (const op of OTHER_PROJECTS) {
      if (low.includes(op) && !isTarget(op)) { issues.push({ sev: 'warn', label: `mentions another audited project "${op}"`, line: i + 1, snippet: ln.trim().slice(0, 90) }); break; }
    }
  }
  return issues;
}

// ── self-test ──
function selfTest() {
  let pass = 0, fail = 0; const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  const dirty = 'Reproduce: bash /tmp/crit-hunt/x/run.sh\nFound via ares wild-hunt after auditing OtherLib.\n<!-- ── INTERNAL — STRIP BEFORE SENDING -->\nReporter: [your-email]\nTODO: confirm';
  const di = lintDisclosure(dirty, { target: 'AcmeVendor/widget' });
  ok('flags local path', di.some((x) => x.label.includes('local filesystem')));
  ok('flags internal tooling name', di.some((x) => x.label.includes('tooling')));
  ok('flags STRIP block', di.some((x) => x.label.includes('STRIP')));
  ok('flags placeholder', di.some((x) => x.label.includes('placeholder')));
  ok('flags TODO', di.some((x) => x.label.includes('TODO')));
  ok('warns on another audited project (OtherLib in an AcmeVendor report)', di.some((x) => x.sev === 'warn' && /otherlib/.test(x.label)));
  const clean = lintDisclosure('# Disclosure — AcmeVendor/widget\nThe parser copies an attacker-controlled length into a fixed buffer.\nReporter: Jane Doe <jane@example.com>', { target: 'AcmeVendor/widget' });
  ok('clean report → no issues', clean.length === 0);
  ok('does not flag the target\'s own name', !lintDisclosure('about AcmeVendor-widget', { target: 'AcmeVendor/widget' }).some((x) => x.sev === 'warn'));
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

function lintFiles(files, target) {
  const all = [];
  for (const fp of files) {
    if (!fs.existsSync(fp)) continue;
    for (const it of lintDisclosure(fs.readFileSync(fp, 'utf8'), { target })) all.push({ ...it, file: path.basename(fp) });
  }
  return all;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) return selfTest();
  const get = (k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
  const dir = get('--dir'); const file = get('--file'); const target = get('--target') || '';
  let files = [];
  if (dir) files = ['disclosure-report.md', 'disclosure-email.txt'].map((f) => path.join(dir, f));
  else if (file) files = [file];
  else { console.error('usage: lint-disclosure --dir <package-dir> | --file <f> [--target "Vendor/Repo"] | --self-test'); process.exit(2); }

  const issues = lintFiles(files, target);
  const blocks = issues.filter((i) => i.sev === 'block');
  const warns = issues.filter((i) => i.sev === 'warn');
  console.log(`\n════════ vendor-cleanliness lint ${target ? `(target: ${target}) ` : ''}════════\n`);
  if (!issues.length) console.log('  ✅ clean — no leaks detected');
  for (const b of blocks) console.log(`  ❌ BLOCK ${b.file}:${b.line} — ${b.label}: "${b.snippet}"`);
  for (const w of warns) console.log(`  ⚠ warn  ${w.file}:${w.line} — ${w.label}: "${w.snippet}"`);
  console.log(`\n  ${blocks.length} blocking · ${warns.length} warning(s)\n`);
  process.exit(blocks.length ? 3 : 0);
}

export { lintDisclosure };
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
