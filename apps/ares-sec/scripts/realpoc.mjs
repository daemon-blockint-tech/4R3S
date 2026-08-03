#!/usr/bin/env node
/**
 * realpoc — the strongest PoC tier: compile the VERBATIM vulnerable function(s)
 * extracted byte-for-byte from the pinned repo, linked with an author-provided
 * prelude (real headers + minimal stubs) and driver (crafts the attacker input),
 * and run under AddressSanitizer. Because the vulnerable code is *extracted from
 * the real source*, not re-typed, a transcription error is structurally
 * impossible — the bug fires in the actual code or not at all.
 *
 * Finding schema — add a `real_poc` block:
 *   "real_poc": {
 *     "language": "cpp"|"c",
 *     "extract": [ { "file": "<repo-relative>", "function": "<unique def substring>" } ],
 *     "prelude": "<C/C++: #include real headers + minimal stubs for deps>",
 *     "driver":  "<C/C++: main() that crafts the attacker input and calls the fn>",
 *     "cflags":  "-I{repo}/include ...",            // {repo} → repo_path
 *     "expect_signature": "AddressSanitizer: ..."
 *   }
 * The repo is finding.repo_path (or --repo). Extracted source + the built TU are
 * written next to the finding's poc dir (gitignored) for audit/reproduction.
 *
 * Usage: node scripts/realpoc.mjs --finding <file.json> [--repo <clone>]
 *        node scripts/realpoc.mjs --self-test
 * Exit 0 = real source compiled + crashed with the expected signature · 1 = no/ wrong crash · 2 = bad input.
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// ── extract a function VERBATIM by a unique substring of its definition line ──
function extractFunction(text, needle) {
  const lines = text.split('\n');
  let start = -1;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(needle) && /\(/.test(lines[i] + (lines[i + 1] || '') + (lines[i + 2] || ''))) { start = i; break; }
  }
  if (start < 0) return null;
  let bi = -1;
  for (let i = start; i < Math.min(lines.length, start + 25); i++) if (lines[i].includes('{')) { bi = i; break; }
  if (bi < 0) return null;
  let bal = 0, end = -1;
  for (let i = bi; i < lines.length; i++) {
    for (const ch of lines[i]) { if (ch === '{') bal++; else if (ch === '}') { bal--; if (bal === 0) { end = i; break; } } }
    if (end >= 0) break;
  }
  if (end < 0) return null;
  return { startLine: start + 1, endLine: end + 1, text: lines.slice(start, end + 1).join('\n') };
}

function selfTest() {
  let pass = 0, fail = 0; const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  const src = ['int unrelated() { return 0; }',
    'void victim(char* dst, unsigned n) {',
    '  char src[8] = {0};',
    '  memcpy(dst, src, n);   // sink',
    '}',
    'int after() { return 1; }'].join('\n');
  const e = extractFunction(src, 'void victim');
  ok('extracts the whole function verbatim', e && /void victim/.test(e.text) && /memcpy\(dst, src, n\)/.test(e.text) && /^}$/m.test(e.text.split('\n').pop() === '}' ? '}' : ''));
  ok('reports correct line span (2-5)', e && e.startLine === 2 && e.endLine === 5);
  ok('does not slurp the trailing function', e && !/int after/.test(e.text));
  ok('returns null for a missing function', extractFunction(src, 'void nope') === null);
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) return selfTest();
  const get = (k) => { const i = argv.indexOf(k); return i >= 0 ? argv[i + 1] : undefined; };
  const findingArg = get('--finding');
  if (!findingArg) { console.error('usage: realpoc --finding <file.json> [--repo <clone>] | --self-test'); process.exit(2); }
  const fp = path.isAbsolute(findingArg) ? findingArg : path.join(REPO, findingArg);
  if (!fs.existsSync(fp)) { console.error(`finding not found: ${fp}`); process.exit(2); }
  const f = JSON.parse(fs.readFileSync(fp, 'utf8'));
  const rp = f.real_poc;
  if (!rp || !rp.extract || !(rp.driver || rp.driver_file)) { console.error('finding has no real_poc { extract, prelude|prelude_file, driver|driver_file, ... } block'); process.exit(2); }
  const pocDir = (f.poc_artifact && f.poc_artifact.dir) ? path.join(REPO, f.poc_artifact.dir) : null;
  const readPart = (inline, file) => inline != null ? inline : (file && pocDir ? fs.readFileSync(path.join(pocDir, file), 'utf8') : '');
  const prelude = readPart(rp.prelude, rp.prelude_file);
  const driver = readPart(rp.driver, rp.driver_file);
  const repo = get('--repo') || f.repo_path;
  if (!repo || !fs.existsSync(repo)) { console.error(`repo clone not found (set finding.repo_path or --repo): ${repo}`); process.exit(2); }

  console.log(`\n════════ realpoc — ${f.slug || f.project} ════════\n`);
  const extracted = [];
  for (const ex of rp.extract) {
    const srcPath = path.join(repo, ex.file);
    if (!fs.existsSync(srcPath)) { console.error(`extract source not found: ${ex.file}`); process.exit(2); }
    const e = extractFunction(fs.readFileSync(srcPath, 'utf8'), ex.function);
    if (!e) { console.error(`could not locate function "${ex.function}" in ${ex.file}`); process.exit(2); }
    console.log(`  extracted VERBATIM: ${ex.file}:${e.startLine}-${e.endLine}  ("${ex.function}", ${e.endLine - e.startLine + 1} lines)`);
    extracted.push(`// ===== VERBATIM from ${ex.file}:${e.startLine}-${e.endLine} (DO NOT EDIT) =====\n${e.text}`);
  }

  const ext = rp.language === 'c' ? 'c' : 'cpp';
  const tu = [prelude || '', '', extracted.join('\n\n'), '', driver].join('\n');
  // write the TU + extracted source next to the poc dir (gitignored) for audit
  const outDir = (f.poc_artifact && f.poc_artifact.dir) ? path.join(REPO, f.poc_artifact.dir) : mkdtempSync(path.join(tmpdir(), 'realpoc-'));
  fs.mkdirSync(outDir, { recursive: true });
  const tuPath = path.join(outDir, `${f.slug || 'finding'}.realpoc.${ext}`);
  fs.writeFileSync(tuPath, tu);
  console.log(`  built TU (prelude + verbatim fn + driver): ${path.relative(REPO, tuPath)}`);

  const cc = ext === 'c' ? 'clang' : 'clang++';
  const std = ext === 'c' ? '-std=c11' : '-std=c++17';
  const cflags = String(rp.cflags || '').replace(/\{repo\}/g, repo).split(/\s+/).filter(Boolean);
  const bin = path.join(outDir, `${f.slug || 'finding'}.realpoc.bin`);
  const build = spawnSync(cc, [std, '-fsanitize=address', '-fno-omit-frame-pointer', '-g', '-O0', ...cflags, tuPath, '-o', bin], { encoding: 'utf8' });
  if (build.status !== 0) {
    console.log(`\n  ❌ BUILD FAILED (the verbatim real source did not compile with the given prelude/cflags):\n`);
    console.log('    ' + String(build.stderr || build.stdout).trim().split('\n').slice(0, 12).join('\n    '));
    process.exit(1);
  }
  console.log(`  ✅ compiled the real source under ASan`);

  const run = spawnSync(bin, [], { encoding: 'utf8', env: { ...process.env, ASAN_OPTIONS: 'abort_on_error=0:exitcode=99' } });
  const outAll = `${run.stdout || ''}\n${run.stderr || ''}`;
  const sig = rp.expect_signature || 'AddressSanitizer';
  const hit = outAll.includes(sig);
  console.log(`  ran it: ${hit ? `💥 reproduced "${sig}"` : 'no expected signature'}`);
  if (hit) { const m = outAll.split('\n').find((l) => l.includes(sig)); if (m) console.log(`     ${m.trim().slice(0, 110)}`); }

  console.log(`\n  ${hit ? '✅ REAL-SOURCE POC CONFIRMED' : '❌ did not reproduce'} — the bug ${hit ? 'fires in the actual repo code (verbatim), not a transcription' : 'did not fire'}\n`);
  process.exit(hit ? 0 : 1);
}

export { extractFunction };
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
