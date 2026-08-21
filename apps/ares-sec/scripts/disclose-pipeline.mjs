#!/usr/bin/env node
/**
 * disclose-pipeline — the SEC-4 coordinated-disclosure PIPELINE. Takes one
 * finding and runs the three confirmation checks against it, in order, then
 * hands off to the drafts-only disclosure generator:
 *
 *     refuter  →  OSV novelty  →  live PoC  →  disclosure-gen (drafts)
 *
 * It is glue, not new analysis: every stage is an EXISTING tool in this repo
 * (refute-finding.mjs, verify-finding.mjs's checkOSV, realpoc.mjs,
 * disclosure-gen.mjs). This script only sequences them, aggregates a verdict,
 * and writes a machine-readable pipeline report next to the finding.
 *
 * DESIGN INVARIANTS (read before editing):
 *   1. DRAFTS ONLY. This pipeline NEVER submits, posts, emails, or files a report
 *      anywhere. It imports nothing from src/integrations/bounty.* and spawns no
 *      submit path. The terminal stage (disclosure-gen) writes files and prints a
 *      human send-checklist — a person reviews and sends. (Enforced by a static
 *      grep in test-disclose-pipeline.mjs.)
 *   2. PERMISSIVE GATE, ONE BLOCKER. Drafts are produced for any finding the
 *      REFUTER does not kill. An OSV duplicate, or a PoC that was gated / did not
 *      reproduce, are ADVISORY flags stamped into the report — not blockers. Only
 *      a majority-REFUTED verdict stops the pipeline before drafting (exit 3).
 *   3. NO SILENT SKIPS. Every stage that is gated off (no toolchain, no LLM key,
 *      --no-net, no real_poc block) says so explicitly in the report and stdout.
 *
 * Stage gating on this machine (and in CI): the OSV query runs by default (needs
 * network); the live PoC auto-skips without a clang/ASan toolchain; the refuter
 * auto-skips without a built dist/ + an LLM key. All three degrade to a reported
 * skip, so the pipeline always reaches the drafts-only stage.
 *
 * Usage:
 *   node scripts/disclose-pipeline.mjs --finding <finding.json>
 *   node scripts/disclose-pipeline.mjs --finding <f> --out <dir> --no-poc
 *   node scripts/disclose-pipeline.mjs --finding <f> --no-net            # fully offline
 *   node scripts/disclose-pipeline.mjs --finding <f> --provider openrouter --refuters 3
 *   node scripts/disclose-pipeline.mjs --self-test                       # offline unit tests
 *
 * Flags:
 *   --finding <file>   the finding JSON (required). Absolute, cwd-relative, or apps/ares-sec-relative.
 *   --out <dir>        disclosure output dir (default: <finding-dir>/<slug>.disclosure).
 *   --no-net           disable all network (OSV skips; refuter is not attempted live).
 *   --no-poc           skip the live-PoC stage entirely.
 *   --no-refute        skip the refuter stage entirely (advisory skip, does NOT block drafts).
 *   --refuters <N>     refuter panel size (default 3), forwarded to refute-finding.
 *   --provider <p>     LLM provider for the refuter (default openrouter), forwarded.
 *   --model <m>        LLM model for the refuter, forwarded.
 *   --repo <path>      repo clone, forwarded to the refuter (cite-check) and realpoc.
 *   --reporter <s>     forwarded to disclosure-gen (scrubbed there unless a role contact).
 *   --days <N>         disclosure timeline window (default 90), forwarded to disclosure-gen.
 *   --format md|email|both   forwarded to disclosure-gen (default both).
 *   --refresh-refutation     re-run the refuter even if a <slug>.refutation_report.json exists.
 *   --verbose          echo each child tool's stdout.
 *
 * Exit: 0 = drafts written (may carry advisory flags) · 3 = REFUTED (no drafts)
 *       · 2 = bad input (no/invalid finding, or missing required disclosure fields).
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { checkOSV } from './verify-finding.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const R = (...p) => path.join(REPO, ...p);

// ── arg parser (same generic --k v style as the sibling scripts) ─────────────
function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) {
      const k = t.slice(2);
      const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true';
      a[k] = v;
    }
  }
  return a;
}
const isFlag = (v) => v === 'true' || v === true;
const val = (v) => (v && v !== 'true' ? v : undefined);

// ── resolve a finding path: absolute, else cwd-relative, else REPO-relative ──
function resolveFinding(p) {
  if (!p || p === 'true') return null;
  if (path.isAbsolute(p)) return p;
  const cwdRel = path.resolve(process.cwd(), p);
  if (fs.existsSync(cwdRel)) return cwdRel;
  return R(p);
}

// ── is a compiler for the finding's real_poc language on PATH? ───────────────
function pocToolchain(language) {
  const cc = language === 'cpp' || language === 'c++' ? 'clang++' : 'clang';
  try {
    const r = spawnSync(cc, ['--version'], { encoding: 'utf8' });
    return { ok: !r.error && r.status === 0, cc };
  } catch {
    return { ok: false, cc };
  }
}

// ── run a sibling node script, capture status + output ───────────────────────
function runScript(script, args, { verbose } = {}) {
  const r = spawnSync(process.execPath, [path.join(HERE, script), ...args], { encoding: 'utf8' });
  if (verbose && r.stdout) console.log(indent(r.stdout));
  if (r.error) return { status: null, stdout: r.stdout || '', stderr: String(r.error.message || r.error) };
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}
const indent = (s) => String(s).split('\n').map((l) => `      ${l}`).join('\n');

// ── refutation report handshake: refute-finding writes <slug>.refutation_report.json ──
function refutationReportPath(findingPath, slug) {
  return path.join(path.dirname(findingPath), `${slug || 'finding'}.refutation_report.json`);
}
function readRefutationReport(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

// =============================================================================
// STAGE 1 — REFUTER (the only blocker)
// =============================================================================
function stageRefuter(findingPath, f, args) {
  const reportPath = refutationReportPath(findingPath, f.slug);

  if (isFlag(args['no-refute']))
    return { status: 'skipped', reason: 'disabled by --no-refute', blocks: false };

  // Reuse an existing adjudication unless asked to refresh — avoids re-spending
  // an LLM panel, and lets an upstream `refute-finding` / `verify --run-refute`
  // decision flow straight through.
  if (!isFlag(args['refresh-refutation']) && fs.existsSync(reportPath)) {
    const rep = readRefutationReport(reportPath);
    if (rep && rep.verdict)
      return summarizeRefutation(rep, 'reused');
  }

  // Attempt a live panel. refute-finding exits 2 when it cannot run (dist/ not
  // built, or no LLM key for the provider). Because we have already validated
  // the finding file, exit 2 here means "refuter unavailable" — a reported skip,
  // not a pipeline error.
  if (isFlag(args['no-net']))
    return { status: 'skipped', reason: 'no live refuter under --no-net (and no cached report)', blocks: false };

  const childArgs = ['--finding', findingPath, '--refuters', String(val(args.refuters) || 3)];
  if (val(args.provider)) childArgs.push('--provider', val(args.provider));
  if (val(args.model)) childArgs.push('--model', val(args.model));
  if (val(args.repo)) childArgs.push('--repo', val(args.repo));

  const r = runScript('refute-finding.mjs', childArgs, { verbose: isFlag(args.verbose) });
  if (r.status === 2)
    return { status: 'skipped', reason: `refuter unavailable (needs built dist/ + LLM key): ${firstLine(r.stderr)}`, blocks: false };
  if (r.status === null)
    return { status: 'skipped', reason: `refuter could not be spawned: ${firstLine(r.stderr)}`, blocks: false };

  const rep = readRefutationReport(reportPath);
  if (!rep || !rep.verdict)
    return { status: 'error', reason: 'refuter ran but wrote no readable report', blocks: false };
  return summarizeRefutation(rep, 'live');
}

function summarizeRefutation(rep, source) {
  const verdict = rep.verdict; // SURVIVED | REFUTED | INCONCLUSIVE
  return {
    status: verdict === 'SURVIVED' ? 'survived' : verdict === 'REFUTED' ? 'refuted' : 'inconclusive',
    verdict,
    refutedCount: rep.refutedCount,
    total: rep.total,
    killing_guards: rep.killing_guards || [],
    source,
    blocks: verdict === 'REFUTED',
  };
}

// =============================================================================
// STAGE 2 — OSV NOVELTY (advisory)
// =============================================================================
async function stageOSV(f, args) {
  const noNet = isFlag(args['no-net']);
  const osv = await checkOSV(f, noNet); // imported, single-sourced from verify-finding
  if (osv.skipped) return { status: 'skipped', reason: osv.skipped };
  if (osv.error) return { status: 'error', reason: osv.error };
  const overlaps = osv.overlaps || [];
  return {
    status: overlaps.length ? 'possible-duplicate' : 'novel',
    count: osv.count,
    ids: osv.ids || [],
    overlaps,
  };
}

// =============================================================================
// STAGE 3 — LIVE PoC (advisory)
// =============================================================================
function stagePoc(findingPath, f, args) {
  if (isFlag(args['no-poc'])) return { status: 'skipped', reason: 'disabled by --no-poc' };
  if (!f.real_poc || !f.real_poc.extract || !f.real_poc.driver)
    return { status: 'n/a', reason: 'no real_poc block in finding' };

  const tc = pocToolchain(f.real_poc.language);
  if (!tc.ok) return { status: 'gated', reason: `no ${tc.cc}/ASan toolchain on PATH` };

  const childArgs = ['--finding', findingPath];
  if (val(args.repo)) childArgs.push('--repo', val(args.repo));
  const r = runScript('realpoc.mjs', childArgs, { verbose: isFlag(args.verbose) });
  if (r.status === 0) return { status: 'reproduced', reason: 'compiled real source crashed with expected signature' };
  if (r.status === 2) return { status: 'bad-input', reason: `realpoc rejected the finding: ${firstLine(r.stderr)}` };
  return { status: 'not-reproduced', reason: `realpoc did not observe the expected crash (exit ${r.status})` };
}

// =============================================================================
// STAGE 4 — DISCLOSURE DRAFTS (drafts only)
// =============================================================================
function stageDisclosure(findingPath, f, outDir, args) {
  const childArgs = ['--finding', findingPath, '--out', outDir];
  if (val(args.format)) childArgs.push('--format', val(args.format));
  if (val(args.reporter)) childArgs.push('--reporter', val(args.reporter));
  if (val(args.days)) childArgs.push('--days', String(val(args.days)));

  const r = runScript('disclosure-gen.mjs', childArgs, { verbose: isFlag(args.verbose) });
  if (r.status === 2)
    return { status: 'bad-input', reason: `disclosure-gen rejected the finding: ${firstLine(r.stderr) || firstLine(r.stdout)}`, files: [] };

  const files = ['disclosure-report.md', 'disclosure-email.txt', 'SEND-CHECKLIST.md']
    .map((n) => path.join(outDir, n))
    .filter((p) => fs.existsSync(p));
  // Guard against a disclosure-gen that exited non-2 (e.g. an uncaught throw →
  // exit 1, or a spawn failure → status null) WITHOUT writing anything. Without
  // this, an empty run would be reported as 'written' and the pipeline would
  // claim DRAFTED / exit 0 with zero drafts.
  if (files.length === 0)
    return { status: 'error', reason: `disclosure-gen wrote no files (exit ${r.status}): ${firstLine(r.stderr) || firstLine(r.stdout)}`, outDir, files };
  // exit 3 = drafts written but disclosure-gen's honesty/lint gate wants review.
  return { status: r.status === 3 ? 'written-needs-review' : 'written', outDir, files };
}

const firstLine = (s) => String(s || '').trim().split('\n')[0] || '';

// =============================================================================
// AGGREGATION
// =============================================================================
/**
 * Decide the pipeline verdict + advisories from the stage results. Pure — unit
 * tested in test-disclose-pipeline.mjs.
 */
export function decideVerdict(stages) {
  const advisories = [];
  if (stages.refuter?.blocks)
    return { verdict: 'REFUTED', exit: 3, advisories };

  if (stages.refuter?.status === 'skipped') advisories.push(`refuter-skipped: ${stages.refuter.reason}`);
  if (stages.refuter?.status === 'inconclusive') advisories.push('refuter-inconclusive (no killing guard found, but panel not conclusive)');
  if (stages.refuter?.status === 'error') advisories.push(`refuter-error: ${stages.refuter.reason}`);
  if (stages.osv?.status === 'possible-duplicate') advisories.push(`osv-possible-duplicate: ${(stages.osv.overlaps || []).join(', ')}`);
  if (stages.osv?.status === 'skipped') advisories.push(`osv-skipped: ${stages.osv.reason}`);
  if (stages.osv?.status === 'error') advisories.push(`osv-error: ${stages.osv.reason}`);
  if (['gated', 'skipped', 'n/a', 'not-reproduced', 'bad-input'].includes(stages.poc?.status)) advisories.push(`poc-${stages.poc.status}: ${stages.poc.reason}`);
  if (stages.disclosure?.status === 'written-needs-review') advisories.push('disclosure-review: honesty/lint gate flagged the draft — resolve before sending');
  if (stages.disclosure?.status === 'error') advisories.push(`disclosure-error: ${stages.disclosure.reason}`);

  // Only a finding that produced actual drafts is DRAFTED. A disclosure stage
  // that rejected the input (bad-input) or wrote nothing (error) is a non-draft
  // failure — never report exit 0 without files on disk.
  const d = stages.disclosure?.status;
  if (d === 'bad-input') return { verdict: 'BAD-INPUT', exit: 2, advisories };
  if (d !== 'written' && d !== 'written-needs-review') return { verdict: 'ERROR', exit: 2, advisories };

  return { verdict: 'DRAFTED', exit: 0, advisories };
}

// =============================================================================
// MAIN
// =============================================================================
async function main() {
  const args = parseArgs(process.argv.slice(2));

  const findingPath = resolveFinding(args.finding);
  if (!findingPath) {
    console.error('usage: node scripts/disclose-pipeline.mjs --finding <finding.json> [--out <dir>] [--no-net] [--no-poc] [--no-refute]');
    process.exit(2);
  }
  if (!fs.existsSync(findingPath)) { console.error(`finding not found: ${findingPath}`); process.exit(2); }
  let f;
  try { f = JSON.parse(fs.readFileSync(findingPath, 'utf8')); }
  catch (e) { console.error(`bad finding JSON: ${e.message}`); process.exit(2); }

  // Fail fast on the fields disclosure-gen requires, so we don't run the
  // refuter/OSV/PoC only to faceplant at the drafting stage.
  const missing = ['slug', 'project', 'component', 'vuln_class', 'summary'].filter((k) => !f[k]);
  if (missing.length) { console.error(`finding missing required fields for disclosure: ${missing.join(', ')}`); process.exit(2); }

  const outDir = val(args.out)
    ? (path.isAbsolute(args.out) ? args.out : path.resolve(process.cwd(), args.out))
    : path.join(path.dirname(findingPath), `${f.slug}.disclosure`);

  console.log(`\n════════ coordinated-disclosure pipeline — ${f.project} · ${f.slug} ════════`);
  console.log(`  drafts-only: this pipeline never sends. Network: ${isFlag(args['no-net']) ? 'OFF (--no-net)' : 'ON (OSV novelty)'}\n`);

  const stages = {};

  // 1. refuter (blocker)
  stages.refuter = stageRefuter(findingPath, f, args);
  logStage('refuter', stages.refuter, refuterLine(stages.refuter));
  if (stages.refuter.blocks) {
    const guards = (stages.refuter.killing_guards || []).map((g) => (typeof g === 'string' ? g : g.file ? `${g.file}:${g.line || '?'}` : JSON.stringify(g)));
    const rep = writeReport(findingPath, f, stages, { verdict: 'REFUTED', exit: 3, advisories: [] }, null);
    console.log(`\n  ❌ REFUTED (${stages.refuter.refutedCount}/${stages.refuter.total}) — NOT drafting a disclosure for a likely false positive.`);
    if (guards.length) console.log(`     killing guard(s): ${guards.join(' · ')}`);
    console.log(`     report: ${path.relative(process.cwd(), rep)}\n`);
    process.exit(3);
  }

  // 2. OSV novelty (advisory)
  stages.osv = await stageOSV(f, args);
  logStage('osv', stages.osv, osvLine(stages.osv));

  // 3. live PoC (advisory)
  stages.poc = stagePoc(findingPath, f, args);
  logStage('poc', stages.poc, `${stages.poc.status} — ${stages.poc.reason || ''}`);

  // 4. disclosure drafts (drafts only)
  stages.disclosure = stageDisclosure(findingPath, f, outDir, args);
  logStage('disclosure', stages.disclosure,
    stages.disclosure.status === 'bad-input' ? stages.disclosure.reason : `${stages.disclosure.files.length} file(s) → ${path.relative(process.cwd(), outDir)}`);

  const decision = decideVerdict(stages);
  const reportPath = writeReport(findingPath, f, stages, decision, decision.verdict === 'DRAFTED' ? { outDir, files: stages.disclosure.files } : null);

  console.log(`\n════════ verdict: ${decision.verdict} ════════`);
  if (decision.advisories.length) {
    console.log(`  advisories (${decision.advisories.length}) — review, but not blocking:`);
    for (const a of decision.advisories) console.log(`     ⚠ ${a}`);
  }
  if (decision.verdict === 'DRAFTED') {
    console.log(`  drafts (DO NOT auto-send):`);
    for (const w of stages.disclosure.files) console.log(`     ${path.relative(process.cwd(), w)}`);
    const checklist = stages.disclosure.files.find((w) => /SEND-CHECKLIST\.md$/.test(w));
    if (checklist) console.log(`  NEXT: open ${path.relative(process.cwd(), checklist)} and work the checklist by hand. This pipeline does NOT send — you do.`);
  }
  console.log(`  report: ${path.relative(process.cwd(), reportPath)}\n`);
  process.exit(decision.exit);
}

function refuterLine(s) {
  if (s.status === 'skipped') return `skipped — ${s.reason}`;
  if (s.verdict) return `${s.verdict} (${s.refutedCount}/${s.total}) [${s.source}]`;
  return s.reason || s.status;
}
function osvLine(s) {
  if (s.status === 'skipped') return `skipped — ${s.reason}`;
  if (s.status === 'error') return `error — ${s.reason}`;
  if (s.status === 'possible-duplicate') return `POSSIBLE DUPLICATE of ${s.overlaps.join(', ')} (of ${s.count} advisories)`;
  return `novel (0 overlaps of ${s.count} advisories)`;
}
function logStage(name, s, detail) {
  const WARN = ['possible-duplicate', 'not-reproduced', 'bad-input', 'written-needs-review', 'inconclusive'];
  const glyph = s.blocks ? '❌'
    : ['skipped', 'gated', 'n/a', 'error'].includes(s.status) ? '⊘'
    : WARN.includes(s.status) ? '⚠'
    : '✅';
  console.log(`  ${glyph} ${name.padEnd(11)} ${detail}`);
}

function writeReport(findingPath, f, stages, decision, drafts) {
  const report = {
    schema: 'ares-sec.disclose-pipeline/v1',
    slug: f.slug,
    project: f.project,
    drafts_only: true,
    verdict: decision.verdict,
    advisories: decision.advisories,
    stages,
    drafts,
    at: new Date().toISOString(),
  };
  const p = path.join(path.dirname(findingPath), `${f.slug}.pipeline-report.json`);
  fs.writeFileSync(p, JSON.stringify(report, null, 2));
  return p;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  if (process.argv.includes('--self-test')) {
    console.error('the self-test lives in scripts/test-disclose-pipeline.mjs — run: npm run test:disclose:pipeline');
    process.exit(2);
  }
  main();
}
