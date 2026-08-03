#!/usr/bin/env node
/**
 * verify-finding — the gate that stands between "the model said so" and
 * "confirmed." It answers Pliny's two questions before a finding is allowed to
 * call itself real:
 *
 *   1. IS IT LEGIT?  — does the cited code actually exist at the pinned commit,
 *      and how far up the evidence ladder have we actually climbed?
 *   2. IS IT NOVEL?  — or is it already in OSV / an advisory / an issue?
 *
 * This is NOT formal verification and does not pretend to be. It is:
 *   - DETERMINISTIC anti-hallucination: every `anchor` (file:line + must_contain)
 *     is checked against the real cloned repo. A finding that cites code which
 *     isn't there is REJECTED. This kills the #1 LLM failure mode (confident
 *     citation of code that doesn't exist / is paraphrased / is at the wrong line).
 *   - AUTHORITATIVE novelty: a live OSV.dev query, plus the manual search URLs.
 *   - HONEST evidence tiering: a finding declares poc_status, and the gate refuses
 *     to stamp anything "CONFIRMED" that hasn't actually been run.
 *   - POC-ARTIFACT BINDING: "poc-executed" is no longer an honor-system string.
 *     A finding claiming execution must carry a `poc_artifact` whose captured
 *     `observed` output literally contains the crash `expect_signature`; with
 *     --run-poc the gate re-runs build_run and confirms the signature live.
 *     This is what makes a PoC "the real deal" instead of a self-report.
 *   - REFUTATION GATE: a CONFIRMED finding must document a disprove attempt
 *     (what would make it NOT a bug, and why that fails) — the strongest
 *     anti-false-positive lever, mirroring the hunt's own refutation_attempted.
 *   - DUP HYGIENE: a dated `novelty_checked` attestation (stale searches flagged),
 *     plus optional --check-head that re-fetches each anchored file at the repo
 *     default branch to confirm the cited code isn't ALREADY PATCHED upstream.
 *
 * Evidence ladder (poc_status), lowest → highest:
 *   claimed          the model asserted it; nobody checked            → REJECT (verify first)
 *   source-verified  a human/tool confirmed the code path + anchors    → NEEDS-POC
 *   poc-built        a runnable PoC exists but wasn't executed here     → NEEDS-POC (note why)
 *   poc-executed     we ran it and observed the crash/overflow/leak     → eligible for CONFIRMED
 *                    (must be backed by a verifiable poc_artifact)
 *
 * Verdicts: CONFIRMED (exit 0) · NEEDS-POC / NEEDS-WORK / REVIEW-NOVELTY (exit 3) ·
 *           REJECT / bad-input (exit 2)
 *
 * Usage:
 *   node scripts/verify-finding.mjs --finding <file.json> [--repo <clone-path>]
 *        [--no-net] [--run-poc] [--check-head] [--novelty-max-age <days>]
 */
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const POC_RANK = { claimed: 0, 'source-verified': 1, 'poc-built': 2, 'poc-executed': 3 };

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

// ── locate the cloned repo for a finding (explicit --repo, or scan /tmp/wild-recon*) ──
function locateRepo(f, explicit) {
  if (explicit && explicit !== 'true') return fs.existsSync(explicit) ? explicit : null;
  if (f.repo_path && fs.existsSync(f.repo_path)) return f.repo_path;
  const m = String(f.repo_url || '').match(/github\.com[/:]([^/]+)\/([^/.]+)/i);
  if (!m) return null;
  const want = `${m[1]}_${m[2]}`.toLowerCase();
  for (const base of ['/tmp']) {
    let dirs = [];
    try { dirs = fs.readdirSync(base).filter((d) => /^wild-recon/.test(d)); } catch { /* ignore */ }
    for (const d of dirs) {
      const cand = path.join(base, d, `${m[1]}_${m[2]}`);
      if (fs.existsSync(cand)) return cand;
      // case-insensitive fallback
      try {
        for (const sub of fs.readdirSync(path.join(base, d))) {
          if (sub.toLowerCase() === want) return path.join(base, d, sub);
        }
      } catch { /* ignore */ }
    }
  }
  return null;
}

// ── DETERMINISTIC: verify every anchor against the real repo ──
function checkAnchors(f, repoPath) {
  const out = { repoPath, results: [], allPass: true, checked: 0 };
  if (!Array.isArray(f.anchors) || f.anchors.length === 0) {
    out.allPass = false; out.missing = true; return out;
  }
  if (!repoPath) { out.allPass = false; out.noRepo = true; return out; }
  const WINDOW = 5; // allow small line drift from the cited number
  for (const a of f.anchors) {
    const fp = path.join(repoPath, a.file);
    const r = { file: a.file, line: a.line, must_contain: a.must_contain, pass: false, note: '' };
    if (!fs.existsSync(fp)) { r.note = 'file not found in repo'; out.allPass = false; out.results.push(r); continue; }
    const lines = fs.readFileSync(fp, 'utf8').split('\n');
    out.checked++;
    if (a.must_contain) {
      const ln = Number(a.line) || 0;
      const lo = Math.max(0, ln - 1 - WINDOW), hi = Math.min(lines.length, ln - 1 + WINDOW + 1);
      let foundAt = -1;
      for (let i = lo; i < hi; i++) if (lines[i] && lines[i].includes(a.must_contain)) { foundAt = i + 1; break; }
      if (foundAt === -1) {
        // also scan the whole file so we can say "present but mis-cited line"
        const anywhere = lines.findIndex((l) => l.includes(a.must_contain)) + 1;
        r.note = anywhere ? `snippet present but at line ${anywhere}, not ~${a.line} (re-anchor)` : `snippet NOT found in file (possible hallucination)`;
        out.allPass = false;
      } else { r.pass = true; r.note = `matched at line ${foundAt}: ${lines[foundAt - 1].trim().slice(0, 80)}`; }
    } else {
      if (Number(a.line) > 0 && Number(a.line) <= lines.length) { r.pass = true; r.note = `line ${a.line}: ${(lines[a.line - 1] || '').trim().slice(0, 80)}`; }
      else { r.note = `line ${a.line} out of range (file has ${lines.length})`; out.allPass = false; }
    }
    out.results.push(r);
  }
  return out;
}

// ── AUTHORITATIVE: OSV novelty query ──
async function checkOSV(f, noNet) {
  if (noNet) return { skipped: 'network disabled (--no-net)' };
  if (!f.package_name || !f.ecosystem) return { skipped: 'no package_name/ecosystem (non-registry target — use manual URLs)' };
  try {
    const r = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ package: { name: f.package_name, ecosystem: f.ecosystem } }),
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return { error: `OSV HTTP ${r.status}` };
    const d = await r.json();
    const vulns = d.vulns || [];
    const cwe = (f.cwe || '').toUpperCase();
    // only specific-looking identifiers (camelCase / snake_case), not generic words
    // like "signature" or "parser" that match every advisory in the project
    const fnTokens = ((f.component || '').match(/[A-Za-z_][A-Za-z0-9_]{3,}/g) || [])
      .filter((t) => /[a-z][A-Z]/.test(t) || t.includes('_'));
    const overlaps = vulns.filter((v) => {
      const hay = `${v.summary || ''} ${v.details || ''}`.toLowerCase();
      if (cwe && hay.includes(cwe.toLowerCase())) return true;
      return fnTokens.some((t) => hay.includes(t.toLowerCase()));
    });
    return { count: vulns.length, ids: vulns.map((v) => v.id), overlaps: overlaps.map((v) => v.id) };
  } catch (e) { return { error: e.message }; }
}

function manualUrls(f) {
  const m = String(f.repo_url || '').match(/github\.com[/:]([^/]+)\/([^/.]+)/i);
  const urls = [];
  if (m) {
    const q = encodeURIComponent((f.component || '').split(/[/(:]/)[0] || m[2]);
    urls.push(`issues+PRs: https://github.com/${m[1]}/${m[2]}/issues?q=${q}`);
    urls.push(`advisories: https://github.com/${m[1]}/${m[2]}/security/advisories`);
  }
  if (f.package_name) urls.push(`OSV web: https://osv.dev/list?q=${encodeURIComponent(f.package_name)}`);
  urls.push(`NVD: https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(f.project || f.package_name || '')}`);
  return urls;
}

// ── class-specific obligation: an OOB-write claim must state the 3 things that make it real ──
function classObligation(f) {
  const cwe = (f.cwe || '').toUpperCase();
  const memoryWrite = /CWE-787|CWE-120|CWE-119/.test(cwe) || /\b(memcpy|overflow|oob write|out-of-bounds write)\b/i.test(`${f.vuln_class} ${f.summary}`);
  if (!memoryWrite) return null;
  const blob = `${f.root_cause || ''} ${f.summary || ''} ${f.impact || ''}`.toLowerCase();
  const gaps = [];
  if (!/(sizeof|fixed|\bbyte|\bbytes\b|destination|dest\b|buffer size|small)/.test(blob)) gaps.push('destination size not stated');
  if (!/(device|attacker|untrusted|response|payload|input).{0,40}(size|length|len|controlled)/.test(blob)) gaps.push('source-length provenance (attacker-controlled?) not stated');
  if (!/(no .{0,20}(check|guard|bound)|without .{0,20}(check|bound|validat)|missing .{0,20}(check|bound))/.test(blob)) gaps.push('absence of a dominating bounds-check not stated');
  return { memoryWrite: true, gaps };
}

// ── PoC ARTIFACT: "poc-executed" must be backed by a real, reproducible artifact ──
// Kills the honor-system loophole where poc_status is just a string. A finding
// that claims execution must carry a `poc_artifact` whose captured `observed`
// output literally contains the crash `expect_signature`. With { run:true } the
// gate re-executes build_run (our own PoC code, repo-local only) and confirms the
// signature appears live — turning a claim into reproduced evidence.
function checkPocArtifact(f, repoRoot, { run = false } = {}) {
  const a = f.poc_artifact;
  const out = { present: !!a, ok: false, ran: false, notes: [] };
  if (!a || typeof a !== 'object') { out.notes.push('no poc_artifact block'); return out; }
  const rel = a.dir || a.file;
  if (!rel) { out.notes.push('poc_artifact has neither dir nor file'); return out; }
  const abs = path.isAbsolute(rel) ? rel : path.join(repoRoot, rel);
  out.path = abs;
  if (!fs.existsSync(abs)) { out.notes.push(`poc_artifact path not found: ${rel}`); return out; }
  const sig = a.expect_signature || a.signature;
  if (!sig) { out.notes.push('poc_artifact.expect_signature missing (what string proves the crash?)'); return out; }
  out.signature = sig;
  const observed = String(a.observed || '');
  if (!observed) out.notes.push('poc_artifact.observed is empty (paste the captured crash output)');
  else if (!observed.includes(sig)) out.notes.push(`captured "observed" does NOT contain the signature "${sig}" — the evidence does not show the bug`);
  else out.observedOk = true;
  if (run) {
    const within = abs === repoRoot || abs.startsWith(repoRoot + path.sep);
    if (!within) out.notes.push('refusing to --run-poc on a path outside the repo');
    else if (!a.build_run) out.notes.push('--run-poc requested but poc_artifact.build_run is not set');
    else {
      const dir = a.dir ? abs : path.dirname(abs);
      const r = spawnSync('bash', ['-lc', a.build_run], { cwd: dir, encoding: 'utf8', timeout: 180000 });
      const liveOut = `${r.stdout || ''}\n${r.stderr || ''}`;
      out.ran = true; out.runExit = r.status;
      out.liveSignature = liveOut.includes(sig);
      if (!out.liveSignature) out.notes.push(`re-ran build_run but live output did NOT contain "${sig}" (exit ${r.status})`);
    }
  }
  out.ok = out.observedOk === true && (!run || out.liveSignature === true);
  return out;
}

// ── REFUTATION: a confirmed finding must document a disprove attempt ──
// The strongest anti-false-positive lever — state what would make this NOT a bug
// and why that doesn't hold. Mirrors the raw hunt's `refutation_attempted`.
function checkRefutation(f) {
  const r = String(f.refutation || f.refutation_attempted || '').trim();
  return { present: r.length >= 40, text: r };
}

// ── ADJUDICATED REFUTATION: an INDEPENDENT refuter panel must have tried to disprove it ──
// Documentation (checkRefutation) is necessary but NOT sufficient: a self-written paragraph is
// not a disprove attempt. CONFIRMED requires an INDEPENDENT adjudicated refutation that SURVIVED
// — scripts/refute-finding.mjs runs N refuters that each hunt for a killing guard, then strict-
// majority votes (REFUTED if > half found one, else SURVIVED). A REFUTED verdict OVERTURNS the
// finding (the automatic version of the DATA_FRAG / false-Fast-CDR catches). Mirrors the executed-
// PoC gate: a located/inline adjudication is a CLAIM until --run-refute re-runs the panel live.
function checkRefutationAdjudication(f, findingPath, { run = false, refuters = 3 } = {}) {
  const out = { present: false, ran: false, verdict: null, refutedCount: 0, total: 0, killing_guards: [], notes: [] };
  const slug = f.slug || 'finding';
  const reportPath = path.join(path.dirname(findingPath), `${slug}.refutation_report.json`);
  const ingest = (adj, source) => {
    if (!adj || typeof adj !== 'object' || !adj.verdict) return false;
    out.present = true;
    out.verdict = String(adj.verdict).toUpperCase();
    out.refutedCount = Number(adj.refutedCount) || 0;
    out.total = Number(adj.total) || 0;
    out.killing_guards = Array.isArray(adj.killing_guards) ? adj.killing_guards.filter(Boolean) : [];
    out.source = source;
    return true;
  };
  if (run) {
    // Re-run the independent refuter panel LIVE — the adjudication cannot be stale or hand-written.
    const r = spawnSync('node', [path.join(REPO, 'scripts', 'refute-finding.mjs'),
      '--finding', findingPath, '--refuters', String(refuters)],
      { cwd: REPO, encoding: 'utf8', timeout: 600000 });
    out.ran = true; out.runExit = r.status;
    try { ingest(JSON.parse(fs.readFileSync(reportPath, 'utf8')), 'live (--run-refute)'); }
    catch { out.notes.push(`--run-refute did not yield ${path.basename(reportPath)} (exit ${r.status}); ${String(r.stderr || '').trim().slice(0, 200)}`); }
    return out;
  }
  // No live run: accept a pre-computed adjudication — inline, or the conventional report file.
  if (f.refutation_adjudication && ingest(f.refutation_adjudication, 'inline f.refutation_adjudication')) return out;
  if (fs.existsSync(reportPath)) {
    try { ingest(JSON.parse(fs.readFileSync(reportPath, 'utf8')), path.basename(reportPath)); }
    catch (e) { out.notes.push(`refutation report present but unreadable: ${e.message}`); }
  }
  return out;
}

// ── NOVELTY ATTESTATION: a recorded, dated dup-search (not just OSV at runtime) ──
// "Already repeated" bugs slip in when the dup search is stale or never recorded.
function checkNoveltyAttestation(f, maxAgeDays = 30, today = null) {
  const nc = f.novelty_checked;
  const out = { present: !!(nc && typeof nc === 'object' && nc.date), stale: false };
  if (!out.present) { out.note = 'no dated novelty_checked block (record the dup search: date + sources + conclusion)'; return out; }
  out.date = nc.date;
  const now = today ? new Date(today) : new Date();
  const then = new Date(nc.date);
  if (!isNaN(then.getTime())) {
    out.ageDays = Math.floor((now - then) / 86400000);
    if (out.ageDays > maxAgeDays) { out.stale = true; out.note = `dup search is ${out.ageDays}d old (> ${maxAgeDays}d) — re-check advisories/issues before sending; bugs get reported between audit and disclosure`; }
  }
  return out;
}

// ── STILL VULNERABLE AT HEAD: is the cited code already patched upstream? ──
// Fetch each anchored file at the repo default branch; if must_contain is GONE,
// the bug may already be fixed → not novel. Directly catches "already repeated".
async function checkHeadStillVulnerable(f, noNet) {
  if (noNet) return { skipped: 'network disabled (--no-net)' };
  const m = String(f.repo_url || '').match(/github\.com[/:]([^/]+)\/([^/.]+)/i);
  if (!m) return { skipped: 'non-GitHub repo — check HEAD manually' };
  if (!Array.isArray(f.anchors) || !f.anchors.length) return { skipped: 'no anchors' };
  const results = [];
  for (const a of f.anchors) {
    if (!a.must_contain) { results.push({ file: a.file, present: null, note: 'no must_contain' }); continue; }
    const url = `https://raw.githubusercontent.com/${m[1]}/${m[2]}/HEAD/${a.file}`;
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
      if (!r.ok) { results.push({ file: a.file, present: null, note: `HTTP ${r.status}` }); continue; }
      const txt = await r.text();
      results.push({ file: a.file, present: txt.includes(a.must_contain) });
    } catch (e) { results.push({ file: a.file, present: null, note: e.message }); }
  }
  const checked = results.filter((r) => r.present !== null);
  const gone = checked.filter((r) => r.present === false);
  return { results, anyGone: gone.length > 0, allGone: checked.length > 0 && gone.length === checked.length, checkedCount: checked.length };
}

// ── REACHABILITY: deterministic dominating-guard scan ─────────────────────────
// The #1 false-positive killer observed in practice: a candidate sink that LOOKS
// unbounded but has an upstream bound check the surfacing model missed — a global
// `if (len > sizeof(dst)) return;` at a function's top, a `> capacity` guard, a
// MIN()/std::min() clamp. This scans the function ENCLOSING the sink for any
// comparison of the attacker-controlled length variable against a size/bound. A hit
// does NOT auto-reject — it FLAGS for reachability review (the guard may or may not
// dominate). It only sees SAME-FUNCTION guards; cross-file guards (e.g. a normalize
// pre-pass in another file) are the LLM refuter stage's job (scripts/refute-finding.mjs).
// Deterministic + offline. Driven by an optional finding.sink = {file,line,length_var}.
function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function enclosingFunctionRange(lines, sinkIdx) {
  // sinkIdx 0-based. Walk UP, brace-matching, but skip control-flow/nested-block
  // openers (if/for/while/switch/case/else/do/try and bare `{`) so we land on the
  // enclosing FUNCTION's opener — not a `case {...}` block. This matters: dominating
  // guards often sit at a function's TOP, outside the switch the sink lives in.
  // Heuristic (ignores braces in comments/strings); capped for cost.
  // Negative ID: skip KNOWN control-flow/block openers; treat any other unmatched
  // `{` as the function opener. Robust to diverse + multi-line function signatures
  // (where positively matching `name(...) {` fails because `(` and `{` are on
  // different lines, as in a multi-line method signature).
  const isBlockOpener = (i) => {
    const here = (lines[i] || '').trim();
    if (/^(if|for|while|switch|else|do|try|catch|case|default)\b/.test(here)) return true;
    if (/^\}\s*(else|while|catch)\b/.test(here)) return true;          // `} else {`, `} while (...)`
    if (/^\{$/.test(here)) {                                           // Allman bare `{`
      const prev = (lines[i - 1] || '').trim();
      return /^(if|for|while|switch|else|do|try|catch|case|default)\b/.test(prev) ||
             (/\)\s*$/.test(prev) && /\b(if|for|while|switch|catch)\b/.test(prev));
    }
    return false;
  };
  const LIMIT = 800;
  let depth = 0, lo = -1;
  outer: for (let i = sinkIdx; i >= 0 && sinkIdx - i < LIMIT; i--) {
    const ln = lines[i] || '';
    for (let c = ln.length - 1; c >= 0; c--) {
      if (ln[c] === '}') depth++;
      else if (ln[c] === '{') {
        if (depth > 0) { depth--; }
        else if (!isBlockOpener(i)) { lo = i; break outer; }          // the function's own brace
        // else: control/block opener at depth 0 — skip it, keep scanning up
      }
    }
  }
  if (lo < 0) lo = Math.max(0, sinkIdx - 80);                          // fallback window if no opener found
  let bal = 0, hi = lines.length;
  for (let i = lo; i < lines.length && i - lo < LIMIT; i++) {
    for (const ch of (lines[i] || '')) {
      if (ch === '{') bal++;
      else if (ch === '}') { bal--; if (bal === 0) { hi = i + 1; i = lines.length; break; } }
    }
  }
  return { lo, hi };
}

function checkDominatingGuard(f, repoPath) {
  const out = { applicable: false, declared: false, scanned: false, guards: [], dominatingCandidates: [] };
  const cwe = (f.cwe || '').toUpperCase();
  const memClass = /CWE-787|CWE-120|CWE-119|CWE-125|CWE-130|CWE-190|CWE-680/.test(cwe) ||
    /\b(memcpy|memmove|overflow|underflow|oob|out-of-bounds|out of bounds)\b/i.test(`${f.vuln_class || ''} ${f.summary || ''}`);
  if (!memClass) return out;
  out.applicable = true;
  const sink = f.sink;
  if (!sink || !sink.file || !sink.length_var) return out; // declared stays false → advisory nudge
  out.declared = true;
  if (!repoPath) return out;
  const fp = path.join(repoPath, sink.file);
  if (!fs.existsSync(fp)) { out.fileMissing = true; return out; }
  const lines = fs.readFileSync(fp, 'utf8').split('\n');
  const sinkIdx = Math.max(0, Math.min((Number(sink.line) || 1) - 1, lines.length - 1));
  const { lo, hi } = enclosingFunctionRange(lines, sinkIdx);
  out.scanned = true; out.range = { from: lo + 1, to: hi };
  const lv = escapeRe(sink.length_var);
  const cmp = new RegExp(`\\b${lv}\\b\\s*(?:<=?|>=?|==)|(?:<=?|>=?|==)\\s*\\b${lv}\\b|\\b(?:std::min|MIN|min)\\s*\\([^)]*\\b${lv}\\b`);
  const boundish = /sizeof|_len\b|_size\b|length|capacity|\bmax\b|MAX|data_len|remain|kMax|MTU|BUFFER|\bbytes\b/i;
  for (let i = lo; i < hi; i++) {
    if (i === sinkIdx) continue;
    const ln = lines[i] || '';
    if (cmp.test(ln)) out.guards.push({ line: i + 1, beforeSink: i < sinkIdx, boundish: boundish.test(ln), text: ln.trim().slice(0, 100) });
  }
  out.dominatingCandidates = out.guards.filter((g) => g.boundish && g.beforeSink);
  return out;
}

// ── SEVERITY EVIDENCE: the CVSS vector must be backed by the reachability text ──
// AV/AC is the crit-vs-high lever (the same write bug is AV:A — capped around High —
// over a serial/LAN transport, but AV:N — up to Critical — over routed UDP; a bug that
// only fires under a non-default config drops AC:L→AC:H). This stops
// asserted-without-evidence inflation by cross-checking the vector against the
// finding's own reachability/summary/impact prose. Deterministic; advisory unless
// --strict-severity. Tuned so honestly-rated findings produce zero flags.
function checkSeverityEvidence(f) {
  const out = { applicable: false, flags: [] };
  if (!f.cvss_vector) return out;
  const m = Object.fromEntries(String(f.cvss_vector).replace(/^CVSS:3\.[01]\//, '').split('/').map((s) => s.split(':')));
  out.applicable = true;
  out.metrics = m;
  const reach = `${f.reachability || ''} ${f.summary || ''} ${f.impact || ''}`.toLowerCase();

  if (m.AV === 'N') {
    const listener = /\b(socket|recvfrom|recv\b|listen|bind|udp|tcp|port|datagram)\b/.test(reach);
    const delivered = /\b(network|remote|inbound|from any (sender|source)|over the (network|wire|internet)|email|message|request|untrusted (input|peer|message)|wire)\b/.test(reach);
    if (!listener && !delivered) out.flags.push('AV:N asserted but no network-listener or network-delivered-input evidence in reachability — confirm network-reachable, else AV:A/AV:L');
    const adjacent = /\b(lan-scoped|\blan\b|adjacent|local segment|same (network|subnet)|multicast|serial|\busb\b|device link|point-to-point)\b/.test(reach);
    const networkClear = /\b(network attacker|over the network|routed|internet|\bwan\b|unauthenticated (peer|network)|flat .{0,15}network|off-segment|av:n)\b/.test(reach);
    if (adjacent && !networkClear) out.flags.push('AV:N but reachability reads as adjacent/local (LAN/serial/multicast/USB) — should this be AV:A? (the adjacency severity lever)');
  }
  if (m.AC === 'L') {
    if (/\b(non-default config|requires .{0,40}(config|configur)|only .{0,25}(when|if) .{0,25}configur|misconfigur|if the (user|deployment|operator) (sets|sizes|configures|enabl)|under-sized|specific configuration)\b/.test(reach))
      out.flags.push('AC:L but reachability rests on a non-default/specific configuration — should this be AC:H? (the config-gate severity lever)');
  }
  if (m.PR === 'N') {
    const unauth = /\b(unauthenticat|no auth|without auth|plaintext|no (per-packet )?(authentication|credential|secret)|anonymous|any sender)\b/.test(reach);
    const needsPriv = /\b(authenticated (session|client|user)|requires .{0,20}(login|credential|session)|after (auth|login)|privileged|logged.?in)\b/.test(reach);
    if (!unauth && needsPriv) out.flags.push('PR:N but reachability implies an authenticated/privileged precondition — confirm PR:N, else PR:L/PR:H');
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.finding || args.finding === 'true') {
    console.error('usage: node scripts/verify-finding.mjs --finding <file.json> [--repo <clone>] [--no-net]');
    process.exit(2);
  }
  const fp = path.isAbsolute(args.finding) ? args.finding : path.join(REPO, args.finding);
  if (!fs.existsSync(fp)) { console.error(`finding not found: ${fp}`); process.exit(2); }
  let f; try { f = JSON.parse(fs.readFileSync(fp, 'utf8')); } catch (e) { console.error(`bad JSON: ${e.message}`); process.exit(2); }

  const reasons = [];
  let verdict = 'CONFIRMED'; // start optimistic, demote on each failed gate
  const demote = (to, why) => { const order = ['CONFIRMED', 'REVIEW-NOVELTY', 'NEEDS-POC', 'NEEDS-WORK', 'REJECT']; if (order.indexOf(to) > order.indexOf(verdict)) verdict = to; reasons.push(why); };

  // gate 1: completeness + honest poc_status
  const poc = String(f.poc_status || '').trim();
  if (!POC_RANK.hasOwnProperty(poc)) demote('NEEDS-WORK', `poc_status missing/invalid (got "${poc || 'none'}"; must be one of ${Object.keys(POC_RANK).join(', ')})`);
  for (const k of ['slug', 'project', 'component', 'cwe', 'vuln_class', 'summary']) if (!f[k]) demote('NEEDS-WORK', `missing field: ${k}`);
  if (!f.reachability || String(f.reachability).trim().length < 20) demote('NEEDS-WORK', 'reachability path not documented (how does untrusted input reach the sink?)');

  // gate 2: DETERMINISTIC anchors
  const repoPath = locateRepo(f, args.repo);
  const anchors = checkAnchors(f, repoPath);
  if (anchors.missing) demote('NEEDS-WORK', 'no anchors declared (cannot machine-verify the cited code)');
  else if (anchors.noRepo) demote('NEEDS-WORK', `repo clone not found (pass --repo); cannot verify anchors`);
  else if (!anchors.allPass) demote('REJECT', 'anchor verification FAILED — cited code not found where claimed (see below)');

  // gate 3: novelty
  const osv = await checkOSV(f, args['no-net']);
  if (osv.overlaps && osv.overlaps.length) demote('REVIEW-NOVELTY', `OSV has advisories that may overlap (${osv.overlaps.join(', ')}) — confirm this isn't a dup`);

  // gate 4: class obligation
  const cls = classObligation(f);
  if (cls && cls.gaps.length) demote('NEEDS-WORK', `OOB-write claim incomplete: ${cls.gaps.join('; ')}`);

  // gate 5: evidence ladder — nothing is CONFIRMED without an executed PoC
  if (POC_RANK[poc] !== undefined && POC_RANK[poc] < POC_RANK['poc-executed']) {
    demote('NEEDS-POC', `evidence is "${poc}", not "poc-executed" — strong but not yet proven by execution`);
  }

  // gate 6: PoC-artifact binding — a "poc-executed" claim must prove itself by
  // ACTUAL RE-EXECUTION, not a pasted "observed" blob. A pasted crash string is a
  // claim; CONFIRMED (disclosure-grade, "executed PoCs only") requires the verifier
  // to re-run build_run and see the signature live. Without --run-poc we cannot
  // prove it, so it can be at most NEEDS-POC — never CONFIRMED.
  const pocArt = checkPocArtifact(f, REPO, { run: !!args['run-poc'] });
  if (poc === 'poc-executed') {
    if (!pocArt.present) demote('NEEDS-WORK', 'poc_status is "poc-executed" but there is no poc_artifact — a claim, not evidence');
    else if (!pocArt.ok) demote('REJECT', `"poc-executed" not backed by evidence: ${pocArt.notes.join('; ')}`);
    else if (!pocArt.ran) demote('NEEDS-POC', '"poc-executed" was NOT re-run by the verifier — a pasted "observed" blob is an unproven claim. Re-run with --run-poc so the crash signature appears in live output before this reaches CONFIRMED.');
    else if (!pocArt.liveSignature) demote('REJECT', 're-ran the PoC but the live output did not contain the crash signature — not reproduced');
  }

  // gate 7: refutation — documented AND independently adjudicated.
  // 7a (documentation): the author states what would make this NOT a bug and why that fails.
  const refut = checkRefutation(f);
  if (!refut.present) demote('NEEDS-WORK', 'no refutation documented — state what would make this NOT a bug and why that fails');
  // 7b (adjudication, MANDATORY for CONFIRMED): an INDEPENDENT refuter panel must have tried to
  // disprove it and the finding must SURVIVE. A REFUTED adjudication OVERTURNS it (false positive).
  const refAdj = checkRefutationAdjudication(f, fp, { run: !!args['run-refute'], refuters: Number(args.refuters) || 3 });
  const guardList = refAdj.killing_guards.map((g) => `${g.file}:${g.line}`).join(', ');
  if (!refAdj.present) demote('NEEDS-WORK', 'no ADJUDICATED refutation — run scripts/refute-finding.mjs (an independent refuter panel) and locate/attach its <slug>.refutation_report.json; a hand-written refutation is not an independent disprove attempt');
  else if (refAdj.verdict === 'REFUTED') demote('REJECT', `independent refuter panel OVERTURNED this: ${refAdj.refutedCount}/${refAdj.total} found a killing guard${guardList ? ` (${guardList})` : ''} — likely a false positive, do NOT disclose`);
  else if (refAdj.verdict === 'INCONCLUSIVE') demote('NEEDS-WORK', 'refuter panel returned INCONCLUSIVE (no parseable verdicts) — re-run scripts/refute-finding.mjs');
  else if (refAdj.total < 2) demote('NEEDS-WORK', `refutation panel too small (total=${refAdj.total}) — need >=2 independent refuters for a real majority`);

  // gate 8: dated novelty attestation (anti-dup / "already repeated")
  const natt = checkNoveltyAttestation(f, Number(args['novelty-max-age']) || 30);
  if (!natt.present || natt.stale) demote('REVIEW-NOVELTY', natt.note);

  // gate 9: still vulnerable at HEAD? (anti-dup / already-fixed-upstream)
  let head = { skipped: 'not requested (pass --check-head)' };
  if (args['check-head']) {
    head = await checkHeadStillVulnerable(f, args['no-net']);
    if (head.anyGone) demote('REVIEW-NOVELTY', `cited code missing at repo HEAD (${head.results.filter((r) => r.present === false).map((r) => r.file).join(', ')}) — may already be patched; confirm you are not reporting a fixed bug`);
  }

  // gate 10: deterministic dominating-guard / reachability scan (anti-false-positive)
  const guard = checkDominatingGuard(f, repoPath);
  if (guard.applicable && guard.declared && guard.dominatingCandidates.length) {
    demote('REVIEW-NOVELTY', `REACHABILITY: an upstream bound check on "${f.sink.length_var}" exists in the sink's function (${guard.dominatingCandidates.map((g) => 'line ' + g.line).join(', ')}) — prove it does NOT dominate the sink before claiming reachability (the #1 false-positive pattern)`);
  }

  // gate 11: severity-evidence — CVSS vector must be backed by reachability (advisory; --strict-severity demotes)
  const sevEv = checkSeverityEvidence(f);
  if (sevEv.flags.length && args['strict-severity']) for (const fl of sevEv.flags) demote('REVIEW-NOVELTY', `SEVERITY: ${fl}`);

  // ── report ──
  console.log(`\n════════ verify-finding — ${f.slug || f.project} ════════\n`);
  console.log(`  poc_status : ${poc || '(none)'}${POC_RANK[poc] !== undefined ? `  (ladder ${POC_RANK[poc]}/3)` : ''}`);
  console.log(`  repo       : ${repoPath || '(not located)'}`);
  console.log(`\n  anchors (deterministic code-existence check):`);
  if (anchors.missing) console.log('    — none declared —');
  else if (anchors.noRepo) console.log('    — repo not found, cannot check —');
  else for (const r of anchors.results) console.log(`    ${r.pass ? '✅' : '❌'} ${r.file}:${r.line} "${r.must_contain || ''}" — ${r.note}`);
  console.log(`\n  novelty (OSV.dev):`);
  if (osv.skipped) console.log(`    skipped — ${osv.skipped}`);
  else if (osv.error) console.log(`    query failed — ${osv.error} (run manual URLs)`);
  else { console.log(`    ${osv.count} advisories${osv.ids.length ? ` (${osv.ids.slice(0, 8).join(', ')}${osv.ids.length > 8 ? '…' : ''})` : ''}`); console.log(`    possible overlap: ${osv.overlaps.length ? osv.overlaps.join(', ') : 'none flagged'}`); }
  console.log(`  manual novelty checks:`);
  for (const u of manualUrls(f)) console.log(`    · ${u}`);
  if (cls && cls.memoryWrite) console.log(`\n  OOB-write obligation: ${cls.gaps.length ? '⚠ ' + cls.gaps.join('; ') : '✅ destination size + source provenance + missing-check all stated'}`);

  console.log(`\n  PoC artifact (poc-executed must prove itself):`);
  if (!pocArt.present) console.log(`    ${poc === 'poc-executed' ? '❌ claims poc-executed but no poc_artifact block' : '— n/a (not poc-executed yet)'}`);
  else {
    console.log(`    path: ${fs.existsSync(pocArt.path || '') ? path.relative(REPO, pocArt.path) : '(missing) ' + (f.poc_artifact.dir || f.poc_artifact.file)}`);
    console.log(`    signature "${pocArt.signature || '?'}" present in captured output: ${pocArt.observedOk ? '✅' : '❌'}`);
    if (pocArt.ran) console.log(`    re-ran build_run: ${pocArt.liveSignature ? '✅ signature reproduced live' : '❌ not reproduced'} (exit ${pocArt.runExit})`);
    else if (f.poc_artifact.build_run) console.log(`    (pass --run-poc to re-execute: \`${f.poc_artifact.build_run}\`)`);
    for (const n of pocArt.notes) console.log(`    · ${n}`);
  }
  if (f.real_poc) console.log(`    ★ real_poc present — strongest tier: compile the VERBATIM repo function (${(f.real_poc.extract || []).map((e) => e.function).join(', ')}). Run: node scripts/realpoc.mjs --finding <this>`);
  console.log(`\n  refutation documented: ${refut.present ? '✅' : '❌ (required for CONFIRMED)'}`);
  console.log(`  refutation adjudicated: ${
    !refAdj.present ? '❌ none — run scripts/refute-finding.mjs (independent panel; required for CONFIRMED)'
    : refAdj.verdict === 'SURVIVED' ? `✅ SURVIVED (${refAdj.refutedCount}/${refAdj.total} refuters found a guard)${refAdj.ran ? ' [live]' : ` [${refAdj.source}]`}`
    : refAdj.verdict === 'REFUTED' ? `❌ REFUTED (${refAdj.refutedCount}/${refAdj.total}${guardList ? ' @ ' + guardList : ''}) — OVERTURNED`
    : `⚠ ${refAdj.verdict} (${refAdj.refutedCount}/${refAdj.total})`}`);
  for (const n of refAdj.notes) console.log(`    · ${n}`);
  console.log(`  novelty attestation : ${natt.present ? (natt.stale ? `⚠ stale (${natt.ageDays}d) — re-check before sending` : `✅ ${natt.date}${natt.ageDays != null ? ` (${natt.ageDays}d old)` : ''}`) : '❌ none recorded'}`);
  if (args['check-head']) {
    console.log(`  still-vulnerable-at-HEAD:`);
    if (head.skipped) console.log(`    skipped — ${head.skipped}`);
    else for (const r of head.results) console.log(`    ${r.present === true ? '✅ present' : r.present === false ? '❌ GONE (maybe patched)' : '?  ' + (r.note || 'unknown')} — ${r.file}`);
  }

  if (guard.applicable) {
    console.log(`\n  reachability — dominating-guard scan (sink length operand):`);
    if (!guard.declared) console.log(`    ⚠ no sink {file,line,length_var} declared — add it so the guard scan can run automatically`);
    else if (!guard.scanned) console.log(`    — could not scan (${guard.fileMissing ? 'sink file not in repo' : 'repo not located'})`);
    else if (guard.dominatingCandidates.length) {
      console.log(`    ⚠ ${guard.dominatingCandidates.length} upstream bound-check(s) on "${f.sink.length_var}" in the sink's function — confirm none dominates:`);
      for (const g of guard.dominatingCandidates) console.log(`       line ${g.line}: ${g.text}`);
    } else console.log(`    ✅ no dominating guard on "${f.sink.length_var}" found in the enclosing function${guard.range ? ` (lines ${guard.range.from}-${guard.range.to})` : ''} — consistent with an unbounded sink`);
  }

  if (sevEv.applicable) {
    console.log(`\n  severity-evidence (CVSS vector vs reachability):`);
    if (!sevEv.flags.length) console.log(`    ✅ ${String(f.cvss_vector).replace('CVSS:3.1/', '')} consistent with the stated reachability`);
    else { for (const fl of sevEv.flags) console.log(`    ⚠ ${fl}`); if (!args['strict-severity']) console.log(`    (advisory — pass --strict-severity to gate on these)`); }
  }

  console.log(`\n  ${verdict === 'CONFIRMED' ? '✅' : verdict === 'REJECT' ? '❌' : '⚠'} VERDICT: ${verdict}`);
  if (reasons.length) for (const r of reasons) console.log(`     - ${r}`);
  else console.log('     - all gates passed');
  console.log('');

  process.exit(verdict === 'CONFIRMED' ? 0 : verdict === 'REJECT' ? 2 : 3);
}

export { checkAnchors, classObligation, locateRepo, manualUrls, POC_RANK,
         checkPocArtifact, checkRefutation, checkRefutationAdjudication, checkNoveltyAttestation, checkHeadStillVulnerable,
         checkDominatingGuard, enclosingFunctionRange, checkSeverityEvidence };

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
