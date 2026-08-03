#!/usr/bin/env node
/**
 * wild-to-finding — convert a raw wild-hunt result (`wild-*.json`) into a
 * GATE-READY finding skeleton (`findings/<slug>.json`). Closes the schema gap that
 * made campaign-1 "predate the gate": the hunter emits {title,file,line,cwe,
 * vulnerable_code,exploit,refutation_attempted}; the gate wants {component,vuln_class,
 * summary,anchors,sink,reachability,refutation,...}. This maps one to the other and
 * seeds the fields the human/gate still needs (poc_artifact, novelty_checked) so a
 * hunt result is instantly runnable through verify-finding.
 *
 * Output is intentionally `poc_status: source-verified` (NOT poc-executed) — a hunt
 * result is a lead, not a confirmation. verify-finding will land it at NEEDS-POC /
 * NEEDS-WORK until a PoC + novelty attestation are added. That is correct.
 *
 * Usage:
 *   node scripts/wild-to-finding.mjs --wild bench/wild-hunt/results/wild-*.json [--index 0] [--slug <slug>] [--stdout]
 *   node scripts/wild-to-finding.mjs --self-test
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// pick a distinctive verbatim line from the hunter's quoted vulnerable_code to anchor on
function pickAnchorSnippet(vulnerable_code) {
  const lines = String(vulnerable_code || '').split('\n').map((l) => l.trim()).filter(Boolean);
  const sink = lines.find((l) => /\b(memcpy|memmove|strcpy|strcat|sprintf)\s*\(/.test(l))
    || lines.find((l) => /\b(malloc|alloca|resize|reserve)\s*\(|\[[^\]]*\]\s*=/.test(l))
    || lines.sort((a, b) => b.length - a.length)[0] || '';
  return sink.replace(/;.*$/, ';').slice(0, 80);   // a stable substring
}
function guessLengthVar(snippet) {
  const m = String(snippet).match(/\b(?:memcpy|memmove)\s*\([^,]+,[^,]+,\s*([A-Za-z_][A-Za-z0-9_.\->]*)/);
  return m ? m[1] : '';
}
function slugify(repo, title) {
  const r = String(repo || 'target').split('/').pop().toLowerCase().replace(/[^a-z0-9]+/g, '-');
  const t = String(title || 'finding').toLowerCase().match(/\b(overflow|oob|out-of-bounds|underflow|recursion|use-after-free|uaf|injection|bypass|leak|dos|memcpy|write|read)\b/g);
  return `${r}-${(t ? [...new Set(t)].slice(0, 2).join('-') : 'finding')}`.slice(0, 60);
}

function convert(wild, index = 0, slugOverride) {
  const finds = wild.findings_high_conf || wild.findings_raw || [];
  const v = finds[index];
  if (!v) return null;
  const snippet = pickAnchorSnippet(v.vulnerable_code);
  const slug = slugOverride || slugify(wild.repo, v.title);
  const memWrite = /CWE-787|CWE-120|CWE-119|CWE-125|CWE-190/.test(v.cwe || '') || /memcpy|overflow|oob/i.test(v.title || '');
  const out = {
    slug,
    project: wild.repo || '',
    ecosystem: null,
    repo_url: wild.repo_url || '',
    versions_affected: `${wild.ref || 'master'} @ ${wild.commit || ''}; please confirm the released-version range against the tags.`,
    commit: wild.commit || '',
    component: `${v.file}${v.line ? ':' + v.line : ''} — ${v.title || ''}`,
    cwe: v.cwe || '',
    vuln_class: v.title || '',
    summary: (v.exploit || v.title || '').split('. ').slice(0, 2).join('. '),
    root_cause: v.exploit || '',
    poc: 'NOT YET REPRODUCED — source-verified lead from the hunter. Build a minimal PoC (ASan harness or a real_poc verbatim compile) before claiming poc-executed.',
    impact: v.exploit || '',
    remediation: 'TODO: state the minimal fix (bound the copy by the destination size / validate the wire length before the sink).',
    cvss_vector: '',
    severity_self: (v.severity || '').replace(/^./, (c) => c.toUpperCase()),
    reporter: 'an independent security researcher',
    novelty: 'TODO: run OSV/GHSA/NVD + a GitHub issue/PR search and record the result.',
    discovery: 'Found by source audit; converted from a hunt result. Hand-verify the anchors + reachability before reporting.',
    poc_status: 'source-verified',
    package_name: null,
    repo_path: '',
    reachability: `${v.preconditions || ''} ${v.exploit || ''}`.trim() || 'TODO: trace how untrusted input reaches the sink (the entry point, the dispatch, why the length/offset is attacker-controlled).',
    refutation: v.refutation_attempted || 'TODO: state what would make this NOT a bug and why that fails.',
    novelty_checked: { date: '', sources: [], conclusion: 'TODO: dated dup-search before sending.' },
    anchors: snippet ? [{ file: v.file, line: v.line || 0, must_contain: snippet }] : [],
  };
  if (memWrite) out.sink = { file: v.file, line: v.line || 0, length_var: guessLengthVar(snippet) || 'TODO' };
  return out;
}

function selfTest() {
  let pass = 0, fail = 0; const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  const wild = { repo: 'acme/widget', repo_url: 'https://github.com/acme/widget', commit: 'abc123', ref: 'master',
    findings_high_conf: [{ title: 'Stack buffer overflow via attacker length', file: 'src/parse.c', line: 88, cwe: 'CWE-787', severity: 'high',
      vulnerable_code: 'uint16_t n = read_u16(p);\n  memcpy(&info.field, &p->data[off], n);', exploit: 'n comes from the wire unbounded; memcpy into a fixed field. Reachable from the UDP handler.', preconditions: 'unauthenticated UDP packet', refutation_attempted: 'no bound on n exists' }] };
  const f = convert(wild);
  ok('produces a slug', /widget/.test(f.slug));
  ok('maps cwe + vuln_class', f.cwe === 'CWE-787' && /overflow/i.test(f.vuln_class));
  ok('builds an anchor from vulnerable_code (verbatim memcpy line)', f.anchors.length === 1 && /memcpy\(&info\.field/.test(f.anchors[0].must_contain) && f.anchors[0].line === 88);
  ok('declares a sink for a write-class finding', !!f.sink && f.sink.length_var === 'n');
  ok('seeds reachability + refutation from the hunt', /UDP/.test(f.reachability) && /no bound/.test(f.refutation));
  ok('marks source-verified (a lead, not a confirmation)', f.poc_status === 'source-verified');
  ok('stubs novelty_checked for the human', f.novelty_checked && f.novelty_checked.date === '');
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) return selfTest();
  const get = (k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
  const wildArg = get('--wild');
  if (!wildArg) { console.error('usage: wild-to-finding --wild <wild-*.json> [--index N] [--slug s] [--stdout] | --self-test'); process.exit(2); }
  const wp = path.isAbsolute(wildArg) ? wildArg : path.join(REPO, wildArg);
  const wild = JSON.parse(fs.readFileSync(wp, 'utf8'));
  if (wild.verdict && wild.verdict !== 'vuln_found') { console.error(`wild result verdict is "${wild.verdict}" (no finding to convert)`); process.exit(2); }
  const f = convert(wild, Number(get('--index')) || 0, get('--slug'));
  if (!f) { console.error('no finding at that index'); process.exit(2); }
  if (argv.includes('--stdout')) { process.stdout.write(JSON.stringify(f, null, 2) + '\n'); process.exit(0); }
  const outPath = path.join(REPO, 'bench/wild-hunt/findings', `${f.slug}.json`);
  fs.writeFileSync(outPath, JSON.stringify(f, null, 2) + '\n');
  console.log(`wrote gate-ready skeleton: ${path.relative(REPO, outPath)}`);
  console.log('next: fill TODO fields (cvss_vector, remediation, novelty_checked), declare repo_path, build a PoC, then run verify-finding.');
}

export { convert, pickAnchorSnippet, slugify };
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
