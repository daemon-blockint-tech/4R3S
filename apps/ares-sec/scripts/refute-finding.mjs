#!/usr/bin/env node
/**
 * refute-finding — the ADVERSARIAL REACHABILITY stage. Complements the deterministic
 * same-function dominating-guard scan in verify-finding.mjs by catching the guards it
 * CAN'T see: a bound/normalize/cap in a DIFFERENT function or file, a config invariant,
 * an auth/CA binding — the things that turned ~10 agent "criticals" into false positives
 * (a normalize/clamp pre-pass in another file, a top-level size cap in a separate
 * function, a cert-is-CA-bound identity invariant, an alloc sized to the same length as
 * the copy). The job of each refuter is NOT to confirm the bug — it is to KILL it.
 *
 * Design:
 *   - Spawn N refuters (default 3). Each is told: "find the dominating check between the
 *     untrusted source and the sink that makes this unreachable/safe; default to REFUTED
 *     if you find one; cite its file:line." Skeptic-by-construction.
 *   - Majority REFUTED -> verdict REFUTED (the finding is likely a false positive; do NOT
 *     claim it until the cited guard is shown not to dominate).
 *   - Otherwise -> SURVIVED (no killing guard found; reachability holds for now).
 *   - Writes <finding-dir>/refutation_report.json for verify-finding / the runbook.
 *
 * Inference runs through the harness's own LLMBackbone (same as wild-hunt.mjs), so it
 * uses whatever provider is configured (openrouter/anthropic/codex/...). It NEVER edits
 * code or runs active probes — read-only reasoning over the cited source.
 *
 * Usage:
 *   node scripts/refute-finding.mjs --finding <file.json> [--refuters 3] [--provider <p>] [--model <m>]
 *   node scripts/refute-finding.mjs --finding <file.json> --dry-run     # print prompts, no inference
 *   node scripts/refute-finding.mjs --self-test                         # offline test of adjudicate()
 *
 * Exit 0 = SURVIVED · 3 = REFUTED / NEEDS-REVIEW · 2 = bad input.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function parseArgs(argv) {
  const a = {};
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t.startsWith('--')) { const k = t.slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : 'true'; a[k] = v; }
  }
  return a;
}

// ── the refuter prompt: a skeptic whose only job is to find the killing guard ──
function buildRefuterPrompt(f, n) {
  return [
    'You are an adversarial vulnerability REFUTER on a coordinated-disclosure team. A teammate claims the vulnerability below. Most such claims are FALSE POSITIVES because a guard the claimant missed makes the sink unreachable or safe. YOUR ONLY JOB is to find that guard and REFUTE the claim. Do not try to confirm it.',
    '',
    `CLAIM #${n}:`,
    `  project: ${f.project}`,
    `  class:   ${f.cwe || ''} ${f.vuln_class || ''}`,
    `  sink:    ${f.sink ? `${f.sink.file}:${f.sink.line} (length operand: ${f.sink.length_var})` : f.component}`,
    `  summary: ${f.summary || ''}`,
    `  reachability claimed: ${f.reachability || '(none stated)'}`,
    '',
    'Look HARD — especially OUTSIDE the sink\'s own function — for any of these that DOMINATES the path from untrusted input to the sink:',
    '  - a bounds / length / capacity check (possibly in a caller, a wrapper, or a pre-pass like a "normalize"/"validate" step in another file)',
    '  - an integer/size invariant that means the bad value cannot actually occur at real input sizes (e.g. a value bounded by a <=64KB datagram can never reach a 2^32 wrap)',
    '  - an allocation sized to the same attacker length (grow-to-fit) so the "overflow" stays in-bounds',
    '  - a config/default invariant that makes the vulnerable configuration non-default (raise attack complexity)',
    '  - an authentication / signature / certificate / CA binding that the claim ignored',
    '',
    'Default to REFUTED if you find a plausible dominating guard. Only return SURVIVED if you genuinely cannot find one after looking in the callers and related files.',
    '',
    'You may reason first, but your reply MUST END with a single JSON object on its own line — no markdown fences, nothing after it. Use exactly one of these two shapes:',
    '  if you found a guard:   {"verdict":"REFUTED","killing_guard":{"file":"path","line":0,"quote":"the guard source"},"why":"one sentence"}',
    '  if you did not:         {"verdict":"SURVIVED","killing_guard":null,"why":"one sentence"}',
  ].join('\n');
}

// ── deterministic adjudication (pure; unit-tested via --self-test) ──
function adjudicate(verdicts) {
  const valid = verdicts.filter((v) => v && (v.verdict === 'REFUTED' || v.verdict === 'SURVIVED'));
  const refuted = valid.filter((v) => v.verdict === 'REFUTED');
  const n = valid.length;
  const majorityRefuted = n > 0 && refuted.length * 2 > n; // strict majority
  return {
    verdict: n === 0 ? 'INCONCLUSIVE' : majorityRefuted ? 'REFUTED' : 'SURVIVED',
    refutedCount: refuted.length,
    total: n,
    killing_guards: refuted.map((v) => v.killing_guard).filter(Boolean),
  };
}

// Reasoning models often emit chain-of-thought prose (which can contain stray
// braces) and/or wrap the answer in ``` fences, then put the real verdict object
// LAST. So: strip fences, scan for every balanced {...} block, and return the
// LAST one that parses to a valid verdict — the model's final answer.
function parseVerdict(text) {
  const s = String(text).replace(/```(?:json)?/gi, '');
  const objects = [];
  let depth = 0, start = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '{') { if (depth === 0) start = i; depth++; }
    else if (c === '}') {
      if (depth > 0 && --depth === 0 && start >= 0) { objects.push(s.slice(start, i + 1)); start = -1; }
    }
  }
  for (let i = objects.length - 1; i >= 0; i--) {
    try {
      const o = JSON.parse(objects[i]);
      if (o && (o.verdict === 'REFUTED' || o.verdict === 'SURVIVED')) return o;
    } catch { /* keep scanning earlier objects */ }
  }
  return null;
}

// GUARD CITE-CHECK (deterministic): an LLM refuter can hallucinate a plausible-looking
// killing guard (e.g. "if (m_id >= ls.w) continue;") that ISN'T in the code, falsely
// refuting a REAL finding. Before counting a REFUTED vote, confirm the cited guard's
// comparison actually appears in the cited source file. Catches the exact failure observed
// on the held wild-hunt targets: real findings refuted via invented or paraphrased-irrelevant guards.
//
// CANONICAL LOGIC: src/mission/adjudicate.ts `guardExistsInSource` — this is a self-contained mirror
// (the CLI must run offline). KEEP THE TWO IN SYNC. Hardened 2026-07-03: the structural fallback now
// requires the cited operands to be the operands of a REAL comparison in source (not two tokens that
// merely co-occur on a line), and the substring path requires the quote to actually LOOK like a guard
// (a comparison / control keyword / bounds-call). Without both, a hallucinated guard whose operand
// strings happen to appear in source could falsely refute — and permanently dedup-block — a real 0-day.
// Reduce source to code-only lines. Mirror of codeLinesOf + langTraits in src/mission/adjudicate.ts —
// keep in sync. Comment/string forms are stripped precisely PER LANGUAGE; the regex-vs-division call is
// avoided entirely — a regex-bearing language blanks each line past its first `/`, a no-regex language
// keeps divisions verbatim. See the TS copy's docstring for the full rationale.
function langTraits(file) {
  const base = { regexAware: false, slashComment: false, blockComment: false, hashComment: false, dashComment: false, pctComment: false, splice: false, pyTriple: false, template: false, rawBacktick: false, cppRaw: false, rustRaw: false, heredoc: false, podDoc: false, perlQuote: false, dollarQuote: false };
  const set = (o) => ({ ...base, ...o });
  const ext = (String(file || '').toLowerCase().match(/\.([a-z0-9+#]+)$/) || [])[1] || '';
  if (/^(js|jsx|mjs|cjs|ts|tsx|mts|cts)$/.test(ext)) return set({ regexAware: true, slashComment: true, blockComment: true, template: true });
  if (/^(cpp|cxx|cc|hpp|hh|hxx|c\+\+|ino|cppm|ixx|tpp|ipp)$/.test(ext)) return set({ slashComment: true, blockComment: true, splice: true, cppRaw: true });
  if (/^(c|h)$/.test(ext)) return set({ slashComment: true, blockComment: true, splice: true });
  if (/^go$/.test(ext)) return set({ slashComment: true, blockComment: true, rawBacktick: true });
  if (/^rs$/.test(ext)) return set({ slashComment: true, blockComment: true, rustRaw: true });
  if (/^(java|kt|kts|scala|swift|cs|dart|groovy|gradle)$/.test(ext)) return set({ slashComment: true, blockComment: true, pyTriple: true });
  if (/^(py|pyi|pyw|pyx)$/.test(ext)) return set({ hashComment: true, pyTriple: true });
  if (/^(sh|bash|zsh|ksh)$/.test(ext)) return set({ hashComment: true, heredoc: 'shell' });
  if (/^(fish|yaml|yml|tf|toml|ini|cfg|conf|dockerfile|mk|cmake|jl|nim|coffee|properties|gitignore)$/.test(ext)) return set({ hashComment: true });
  if (/^php\d*$/.test(ext)) return set({ slashComment: true, blockComment: true, hashComment: true, heredoc: 'php' });
  if (/^(sql|hql|psql|pgsql|ddl)$/.test(ext)) return set({ dashComment: true, blockComment: true, dollarQuote: true });
  if (/^(lua|hs|lhs|elm|adb|ads)$/.test(ext)) return set({ dashComment: true });
  if (/^(erl|hrl|tex|latex)$/.test(ext)) return set({ pctComment: true });
  return set({ regexAware: true, slashComment: true, blockComment: true, hashComment: true, dashComment: true, pctComment: true, pyTriple: true, rawBacktick: true, heredoc: 'ruby', podDoc: true, perlQuote: true });
}
function codeLinesOf(src, t) {
  const n = src.length;
  let masked = '';
  const heredocs = [];
  const isIdent = (ch) => ch !== undefined && /[A-Za-z0-9_$]/.test(ch);
  const blank = (len) => { if (len > 0) masked += ' '.repeat(len); };
  const emitEsc = (i) => {
    if (src[i + 1] === '\n') { masked += '\n'; return i + 2; }
    if (src[i + 1] === '\r' && src[i + 2] === '\n') { masked += '\n'; return i + 3; }
    masked += ' '; return i + 2;
  };
  const skipLineComment = (i, splice) => {
    for (;;) {
      while (i < n && src[i] !== '\n') i++;
      if (splice) { let k = i - 1; if (src[k] === '\r') k--; if (k >= 0 && src[k] === '\\') { masked += '\n'; i++; continue; } }
      return i;
    }
  };
  const blankToClose = (j, close) => {
    while (j < n && src.slice(j, j + close.length) !== close) { masked += src[j] === '\n' ? '\n' : ' '; j++; }
    const end = Math.min(j + close.length, n);
    blank(end - j);
    return end;
  };
  const PERL_PAIR = { '(': ')', '{': '}', '[': ']', '<': '>' };
  const scanPerlQuote = (i) => {
    const m = src.slice(i, i + 3).match(/^(qq|qw|qr|qx|tr|q|m|s|y)(?![A-Za-z0-9_])/);
    if (!m) return -1;
    const op = m[1];
    let j = i + op.length;
    while (src[j] === ' ' || src[j] === '\t') j++;
    const open = src[j];
    if (!open || /[A-Za-z0-9_\s=,;)\]}>]/.test(open)) return -1;
    const twoBody = op === 's' || op === 'tr' || op === 'y';
    blank(j - i + 1); j++;
    const scanBody = (o, cl) => {
      let depth = 1;
      while (j < n) {
        const d = src[j];
        if (d === '\\') { masked += ' '; masked += src[j + 1] === '\n' ? '\n' : ' '; j += 2; continue; }
        if (PERL_PAIR[o] && d === o) depth++;
        else if (d === cl) { depth--; if (depth === 0) { blank(1); j++; return; } }
        masked += d === '\n' ? '\n' : ' '; j++;
      }
    };
    scanBody(open, PERL_PAIR[open] ?? open);
    if (twoBody) {
      let o2 = open, c2 = PERL_PAIR[open] ?? open;
      if (PERL_PAIR[open]) { while (src[j] === ' ' || src[j] === '\t') j++; o2 = src[j]; c2 = PERL_PAIR[o2] ?? o2; if (o2) { blank(1); j++; } }
      scanBody(o2, c2);
    }
    return j;
  };
  const scanTemplate = (i) => {
    masked += ' '; i++;
    const stk = ['`'];
    while (i < n && stk.length > 0) {
      const d = src[i];
      if (d === '\\') { i = emitEsc(i); continue; }
      const top = stk[stk.length - 1];
      if (top === '`') {
        if (d === '`') { stk.pop(); masked += ' '; i++; continue; }
        if (d === '$' && src[i + 1] === '{') { stk.push('{'); masked += '  '; i += 2; continue; }
      } else if (top === '"' || top === "'") {
        if (d === top) { stk.pop(); masked += ' '; i++; continue; }
        if (d === '\n') { stk.pop(); masked += '\n'; i++; continue; }
      } else { // ${…} interpolation — BLANK it (display text, not a bounds guard; and an interpolation
        if (d === '}') { stk.pop(); masked += ' '; i++; continue; } //   reached through a nested template
        if (d === '{') { stk.push('{'); masked += ' '; i++; continue; } //   must never leak — false-VERIFY)
        if (d === '`') { stk.push('`'); masked += ' '; i++; continue; }
        if (d === '"' || d === "'") { stk.push(d); masked += ' '; i++; continue; }
      }
      masked += d === '\n' ? '\n' : ' '; i++;
    }
    return i;
  };
  for (let i = 0; i < n; ) {
    const c = src[i], c2 = src[i + 1];
    if (t.podDoc && (i === 0 || src[i - 1] === '\n')) {
      let le = i; while (le < n && src[le] !== '\n') le++;
      // __END__/__DATA__ must be at column 0 to be a Perl trailer — test from the line's first char (not
      // a trimmed copy) so an indented one is treated as ordinary code, not over-blanked to EOF.
      if (/^__(?:END|DATA)__\b/.test(src.slice(i, le))) { while (i < n) { masked += src[i] === '\n' ? '\n' : ' '; i++; } continue; }
      if (c === '=' && /[A-Za-z]/.test(c2) && /\n=cut\b/.test(src.slice(i))) {
        for (;;) {
          let j = i; while (j < n && src[j] !== '\n') j++;
          const isCut = /^=cut\b/.test(src.slice(i, j));
          blank(j - i); i = j;
          if (i < n) { masked += '\n'; i++; }
          if (isCut || i >= n) break;
        }
        continue;
      }
    }
    if (t.perlQuote && (c === 'q' || c === 'm' || c === 's' || c === 'y' || c === 't') && !isIdent(src[i - 1])) {
      const j = scanPerlQuote(i);
      if (j >= 0) { i = j; continue; }
    }
    if (t.slashComment && c === '/' && c2 === '/') { i = skipLineComment(i, t.splice); continue; }
    if (t.hashComment && c === '#') { i = skipLineComment(i, false); continue; }
    if (t.dashComment && c === '-' && c2 === '-') { i = skipLineComment(i, false); continue; }
    if (t.pctComment && c === '%') { i = skipLineComment(i, false); continue; }
    if (t.blockComment && c === '/' && c2 === '*') {
      i += 2; while (i < n && !(src[i] === '*' && src[i + 1] === '/')) { if (src[i] === '\n') masked += '\n'; i++; } i += 2; continue;
    }
    if (t.cppRaw && !isIdent(src[i - 1])) {
      const m = src.slice(i, i + 4).match(/^(u8R|uR|UR|LR|R)"/);
      if (m) {
        let j = i + m[0].length, delim = '';
        while (j < n && src[j] !== '(' && src[j] !== '\n' && src[j] !== ' ' && src[j] !== '\\' && delim.length <= 16) { delim += src[j]; j++; }
        if (src[j] === '(') { blank(j - i + 1); i = blankToClose(j + 1, ')' + delim + '"'); continue; }
      }
    }
    if (t.rustRaw && !isIdent(src[i - 1])) {
      const m = src.slice(i, i + 260).match(/^b?r(#*)"/);
      if (m) { blank(m[0].length); i = blankToClose(i + m[0].length, '"' + m[1]); continue; }
    }
    if (t.heredoc === 'php' && c === '<' && c2 === '<' && src[i + 2] === '<') { // PHP <<<WORD here/nowdoc
      let j = i + 3;
      while (src[j] === ' ' || src[j] === '\t') j++;
      let q = ''; if (src[j] === "'" || src[j] === '"') { q = src[j]; j++; }
      let w = ''; while (j < n && /[A-Za-z0-9_]/.test(src[j])) { w += src[j]; j++; }
      if (q && src[j] === q) j++;
      if (w) { blank(j - i); heredocs.push({ w, indent: true, php: true }); i = j; continue; }
    }
    if ((t.heredoc === 'shell' || t.heredoc === 'ruby') && c === '<' && c2 === '<' && src[i + 2] !== '<' && src[i + 2] !== '=' && src[i - 1] !== '<') {
      let j = i + 2;
      const squig = src[j] === '-' || src[j] === '~'; if (squig) j++;
      if (t.heredoc === 'shell') while (src[j] === ' ' || src[j] === '\t') j++;
      let q = ''; if (src[j] === "'" || src[j] === '"' || src[j] === '`') { q = src[j]; j++; }
      let w = ''; while (j < n && /[A-Za-z0-9_]/.test(src[j])) { w += src[j]; j++; }
      if (q && src[j] === q) j++;
      const bareOk = w && !squig && !q && t.heredoc !== 'shell' && new RegExp('\\n[ \\t]*' + w + '[ \\t\\r]*(?:\\n|$)').test(src.slice(j));
      if (w && (t.heredoc === 'shell' || squig || q || bareOk)) { blank(j - i); heredocs.push({ w, indent: squig || bareOk }); i = j; continue; }
    }
    if (t.dollarQuote && c === '$') {
      let k = i + 1; while (k < n && /[A-Za-z0-9_]/.test(src[k])) k++;
      if (src[k] === '$') { const tag = src.slice(i, k + 1); blank(tag.length); i = blankToClose(k + 1, tag); continue; }
    }
    if (t.pyTriple && (c === '"' || c === "'") && src[i + 1] === c && src[i + 2] === c) {
      blank(3); let j = i + 3;
      while (j < n && !(src[j] === c && src[j + 1] === c && src[j + 2] === c)) {
        if (src[j] === '\\') { j = emitEsc(j); continue; }
        masked += src[j] === '\n' ? '\n' : ' '; j++;
      }
      if (j < n) { blank(3); j += 3; }
      i = j; continue;
    }
    if (t.template && c === '`') { i = scanTemplate(i); continue; }
    if (t.rawBacktick && c === '`') {
      masked += ' '; i++;
      while (i < n && src[i] !== '`') { masked += src[i] === '\n' ? '\n' : ' '; i++; }
      masked += ' '; if (src[i] === '`') i++;
      continue;
    }
    if (c === '"' || c === "'") {
      masked += ' '; i++;
      while (i < n && src[i] !== c) {
        if (src[i] === '\\') { i = emitEsc(i); continue; }
        if (src[i] === '\n') break;
        masked += ' '; i++;
      }
      masked += ' '; if (src[i] === c) i++;
      continue;
    }
    if (c === '\n') {
      masked += '\n'; i++;
      while (heredocs.length > 0) {
        const hd = heredocs.shift();
        for (;;) {
          let j = i; while (j < n && src[j] !== '\n') j++;
          const stripped = src.slice(i, j).replace(/\r$/, '');
          blank(j - i); i = j;
          const isTerm = hd.php ? new RegExp('^[ \\t]*' + hd.w + '(?![A-Za-z0-9_])').test(stripped)
            : (hd.indent ? stripped.trim() === hd.w : stripped === hd.w);
          if (i < n) { masked += '\n'; i++; }
          if (isTerm || i >= n) break;
        }
      }
      continue;
    }
    masked += c; i++;
  }
  const lines = masked.split('\n');
  if (!t.regexAware) return lines;
  return lines.map((line) => {
    const first = line.indexOf('/');
    return first === -1 ? line : line.slice(0, first) + ' '.repeat(line.length - first);
  });
}
function guardExistsInSource(g, repoRoot) {
  if (!g || !g.file || !g.quote) return 'no-quote';
  let src;
  try { src = fs.readFileSync(path.join(repoRoot, g.file), 'utf8'); } catch { return 'file-missing'; }
  const norm = (s) => String(s).replace(/\s+/g, '').toLowerCase();
  const coreToken = (s) => norm(s).replace(/^[($@%\s]+/, '').replace(/[)\s;,]+$/, '');
  const CMP = '([\\w.()\\[\\]>_$@-]+)\\s*(>=|<=|==|!=|>|<)\\s*([\\w.()\\[\\]>_$@-]+)';
  const GUARD_SHAPE = /(?:>=|<=|==|!=)|\b(?:if|else|return|break|continue|throw|goto)\b|\b(?:assert|clamp|min|max|bound|bounded|validate|sanitize|require|abort|reject|checked?|verify|ensure|limit)\s*\(/i;
  // reduce to code-only lines (strip comments + BLANK string/template-literal contents), match PER
  // line — so a guard that lives only in a comment or string can't false-verify, a `//` inside a
  // string isn't mistaken for a comment, and a quote can't stitch across two unrelated lines.
  const codeLines = codeLinesOf(src, langTraits(g.file));
  const q = norm(g.quote);
  if (q.length >= 6 && GUARD_SHAPE.test(g.quote) && codeLines.some((l) => norm(l).includes(q))) return 'verified';
  const MIRROR = { '>': '<', '<': '>', '>=': '<=', '<=': '>=', '==': '==', '!=': '!=' };
  const cited = String(g.quote).match(new RegExp(CMP));
  if (cited) {
    const a = coreToken(cited[1]), b = coreToken(cited[3]), op = cited[2];
    if (a && b && a !== b) {
      for (const line of codeLines) {
        const re = new RegExp(CMP, 'g');
        let m;
        while ((m = re.exec(line)) !== null) {
          const la = coreToken(m[1]), lb = coreToken(m[3]), lop = m[2];
          // A source `<` whose right operand is immediately followed by `,`, `>`, or `<` opens a GENERIC
          // argument list (`Map<K, V>`, `Vec<u8>`, `Nested<Vec<…>>`), not a comparison — skip it.
          if (lop === '<') {
            const nextCh = (line.slice(re.lastIndex).match(/^\s*(\S)/) ?? [])[1];
            if (nextCh === ',' || nextCh === '>' || nextCh === '<') continue;
          }
          // operands AND operator must match — same order, or reversed with a mirrored operator.
          // The operator is the whole meaning of a bounds guard: a cited `idx >= len` must not verify
          // against a source `idx == len`.
          if (la === a && lb === b && lop === op) return 'verified';
          if (la === b && lb === a && lop === MIRROR[op]) return 'verified';
        }
      }
    }
  }
  return 'hallucinated';
}

// MANDATORY, FAIL-SAFE cite-check (mirrors src/mission/adjudicate.ts's mandatory semantics): a
// REFUTED vote can only stand if it cites a killing guard that ACTUALLY EXISTS in source. Any
// REFUTE that is guardless, empty-quote, hallucinated/file-missing, OR unverifiable because no repo
// was supplied is downgraded to SURVIVED. Rationale: the finder is cheap, but a hallucinated guard
// that refutes a real 0-day is catastrophic — dedup then permanently blocks re-finding it. So an
// unverifiable refutation must NEVER win. Pure + in-place; unit-tested via --self-test.
export function applyCiteCheck(verdicts, repoRoot) {
  for (const v of (verdicts || [])) {
    if (!v || v.verdict !== 'REFUTED') continue;
    const g = v.killing_guard;
    if (!g || !String(g.quote || '').trim()) {
      v.guard_check = 'guardless'; v.original_verdict = 'REFUTED'; v.verdict = 'SURVIVED';
      console.log(`    ⚠ REFUTED vote cites no verifiable guard (guardless/empty-quote) — downgraded to SURVIVED`);
      continue;
    }
    if (!repoRoot) {
      v.guard_check = 'unchecked-no-repo'; v.original_verdict = 'REFUTED'; v.verdict = 'SURVIVED';
      console.log(`    ⚠ no --repo to cite-check ${g.file}:${g.line} — unverifiable REFUTE downgraded to SURVIVED (fail-safe)`);
      continue;
    }
    const gc = guardExistsInSource(g, repoRoot);
    v.guard_check = gc;
    if (gc === 'hallucinated' || gc === 'file-missing') {
      v.original_verdict = 'REFUTED'; v.verdict = 'SURVIVED';
      console.log(`    ⚠ killing-guard NOT in source (${gc}) — REFUTED vote rejected: ${g.file}:${g.line} "${String(g.quote).slice(0, 48)}"`);
    }
  }
  return verdicts;
}

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  ok('2 of 3 REFUTED → REFUTED', adjudicate([{ verdict: 'REFUTED' }, { verdict: 'REFUTED' }, { verdict: 'SURVIVED' }]).verdict === 'REFUTED');
  ok('1 of 3 REFUTED → SURVIVED', adjudicate([{ verdict: 'REFUTED' }, { verdict: 'SURVIVED' }, { verdict: 'SURVIVED' }]).verdict === 'SURVIVED');
  ok('0 valid → INCONCLUSIVE', adjudicate([null, { verdict: 'junk' }]).verdict === 'INCONCLUSIVE');
  ok('collects killing guards', adjudicate([{ verdict: 'REFUTED', killing_guard: { file: 'x', line: 9 } }, { verdict: 'REFUTED', killing_guard: { file: 'x', line: 9 } }]).killing_guards.length === 2);
  ok('parseVerdict extracts JSON', parseVerdict('blah {"verdict":"SURVIVED","killing_guard":null,"why":"none"} tail')?.verdict === 'SURVIVED');
  ok('parseVerdict ignores prose braces, takes last verdict', parseVerdict('I see memcpy(&info, x) {note} reasoning...\n```json\n{"verdict":"REFUTED","killing_guard":{"file":"a.c","line":5,"quote":"if(n>cap)return"},"why":"bounded"}\n```')?.verdict === 'REFUTED');
  ok('parseVerdict returns null on reasoning-only (no JSON)', parseVerdict('Let me trace the path: 1. UDP reception 2. routing — truncated') === null);
  // cite-check mirror parity with src/mission/adjudicate.ts (regex-literal tokenizing + operator match).
  // Each case fails under the OLD logic and passes under the fixed logic — pins the port faithfully.
  const _tmp = fs.mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'refute-st-'));
  const _fix = (name, body) => { fs.writeFileSync(path.join(_tmp, name), body); return name; };
  const _gv = (file, quote) => guardExistsInSource({ file, quote }, _tmp);
  ok('cite: guard after a quote-bearing regex still verifies',
    _gv(_fix('a.js', "s = s.replace(/'/g, 'x');\nif (userId >= tenant.limit) throw e;\n"), 'userId >= tenant.limit') === 'verified');
  ok('cite: a comparison only inside a regex is NOT verified',
    _gv(_fix('b.js', 'const re = /idx >= len/; return arr[idx];\n'), 'idx >= len') === 'hallucinated');
  ok('cite: wrong operator (cited >= vs source ==) is NOT verified',
    _gv(_fix('c.c', 'if (idx == len) return -1;\nreturn arr[idx];\n'), 'idx >= len') === 'hallucinated');
  ok('cite: reversed-order mirror (cited cap < n vs source n > cap) verifies',
    _gv(_fix('d.c', 'if (n > cap) return;\n'), 'cap < n') === 'verified');
  fs.rmSync(_tmp, { recursive: true, force: true });
  // applyCiteCheck — the automated-path fix: an unverifiable REFUTE must NEVER silently bury a finding
  ok('citeCheck: guardless REFUTED → SURVIVED', (() => { const vs = [{ verdict: 'REFUTED' }]; applyCiteCheck(vs, null); return vs[0].verdict === 'SURVIVED' && vs[0].guard_check === 'guardless'; })());
  ok('citeCheck: empty-quote REFUTED → SURVIVED', (() => { const vs = [{ verdict: 'REFUTED', killing_guard: { file: 'a', line: 1, quote: '   ' } }]; applyCiteCheck(vs, null); return vs[0].verdict === 'SURVIVED'; })());
  ok('citeCheck: no-repo unverifiable REFUTED → SURVIVED (fail-safe)', (() => { const vs = [{ verdict: 'REFUTED', killing_guard: { file: 'a', line: 1, quote: 'if (n > cap) return' } }]; applyCiteCheck(vs, null); return vs[0].verdict === 'SURVIVED' && vs[0].guard_check === 'unchecked-no-repo'; })());
  ok('citeCheck: SURVIVED votes untouched', (() => { const vs = [{ verdict: 'SURVIVED' }]; applyCiteCheck(vs, null); return vs[0].verdict === 'SURVIVED' && !vs[0].original_verdict; })());
  ok('citeCheck: hallucinated guard (not in source) → SURVIVED', (() => { const t = fs.mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'cc-')); fs.writeFileSync(path.join(t, 'x.c'), 'return arr[idx];\n'); const vs = [{ verdict: 'REFUTED', killing_guard: { file: 'x.c', line: 1, quote: 'if (idx >= len) return -1' } }]; applyCiteCheck(vs, t); fs.rmSync(t, { recursive: true, force: true }); return vs[0].verdict === 'SURVIVED' && vs[0].guard_check === 'hallucinated'; })());
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args['self-test']) return selfTest();
  if (!args.finding || args.finding === 'true') { console.error('usage: node scripts/refute-finding.mjs --finding <file.json> [--refuters 3] [--dry-run] [--self-test]'); process.exit(2); }
  const fp = path.isAbsolute(args.finding) ? args.finding : path.join(REPO, args.finding);
  if (!fs.existsSync(fp)) { console.error(`finding not found: ${fp}`); process.exit(2); }
  const f = JSON.parse(fs.readFileSync(fp, 'utf8'));
  const refuters = Number(args.refuters) || 3;

  console.log(`\n════════ refute-finding — ${f.slug || f.project} (${refuters} refuters) ════════\n`);

  if (args['dry-run']) {
    console.log(buildRefuterPrompt(f, 1));
    console.log('\n[dry-run] no inference performed. Drop --dry-run (and configure a provider) to run the refuters.');
    process.exit(0);
  }

  // real run: route through the harness's LLMBackbone (same backend wild-hunt uses).
  // Build the config via ConfigManager.getLLMConfig so the API key (from .env / env),
  // a default model, and the fallback chain are all resolved — a bare
  // { provider, model } object carries no apiKey and would fail auth.
  let LLMBackbone, config;
  try {
    ({ LLMBackbone } = await import('../dist/llm/index.js'));
    ({ config } = await import('../dist/config/index.js'));
  }
  catch (e) { console.error(`could not load harness from dist (build first: npm run build). ${e.message}`); process.exit(2); }
  const llmConfig = config.getLLMConfig(args.provider || 'openrouter', args.model);
  // codex/local/mock are command-based (subscription CLI or local) — no API key needed.
  const KEYLESS_PROVIDERS = ['codex', 'local', 'mock'];
  if (!llmConfig.apiKey && !KEYLESS_PROVIDERS.includes(llmConfig.provider)) {
    console.error(`no API key for provider "${llmConfig.provider}" — set ${llmConfig.provider.toUpperCase()}_API_KEY in .env or the environment.`);
    process.exit(2);
  }
  const backbone = new LLMBackbone(llmConfig);

  const verdicts = [];
  // DIVERSITY: spread the refuters across a temperature ladder (low→high) so the panel
  // explores genuinely different reasoning paths instead of returning N verbatim-identical
  // votes. A single backbone at one temperature is an echo, not a panel — the low-temp
  // refuters drill the cited path precisely, the high-temp ones probe unconventional killing
  // guards. (Next step for full independence: rotate the model per refuter too.)
  const refuterTemp = (i) => (refuters > 1 ? +(0.2 + 0.8 * (i - 1) / (refuters - 1)).toFixed(2) : 0.5);
  for (let i = 1; i <= refuters; i++) {
    const temp = refuterTemp(i);
    try {
      // generous budget: reasoning models burn tokens thinking before they emit
      // the final JSON verdict — too small a cap truncates mid-reasoning (no JSON).
      const res = await backbone.chat([{ role: 'user', content: buildRefuterPrompt(f, i) }], { maxTokens: 2000, temperature: temp });
      let raw = res?.content ?? res;
      let v = parseVerdict(raw);
      // a verbose reasoner can exhaust even 2000 tokens before landing the JSON.
      // one terse, reasoning-free retry guarantees a verdict rather than silently
      // dropping this refuter (which would weaken the majority on a real finding).
      if (!v) {
        if (process.env.REFUTE_DEBUG) { const r = String(raw); console.log(`    ↳ refuter ${i} unparseable [${r.length}ch], retrying json-only; tail: ${JSON.stringify(r.slice(-200))}`); }
        const retryPrompt = `${buildRefuterPrompt(f, i)}\n\nOutput ONLY the single JSON object now. No reasoning, no prose, no markdown — just the object.`;
        const res2 = await backbone.chat([{ role: 'user', content: retryPrompt }], { maxTokens: 600, temperature: temp });
        raw = res2?.content ?? res2;
        v = parseVerdict(raw);
      }
      if (v) v.temp = temp;
      verdicts.push(v);
      console.log(`  refuter ${i} (t=${temp}): ${v ? v.verdict : 'unparseable'}${v?.killing_guard ? ` — guard @ ${v.killing_guard.file}:${v.killing_guard.line}` : ''}`);
      if (!v && process.env.REFUTE_DEBUG) { const r = String(raw); console.log(`    ↳ raw[${r.length}ch] tail: ${JSON.stringify(r.slice(-300))}`); }
    } catch (e) { console.log(`  refuter ${i} (t=${temp}): error — ${e.message}`); verdicts.push(null); }
  }

  // CITE-CHECK (MANDATORY + FAIL-SAFE): downgrade every unverifiable REFUTE (guardless / empty-quote /
  // hallucinated / not-in-source / no-repo-to-check) to SURVIVED, so a hallucinated guard can never
  // silently bury a real finding. cli-hunt now always passes --repo; the no-repo path stays fail-safe.
  applyCiteCheck(verdicts, (args.repo && args.repo !== 'true') ? path.resolve(args.repo) : null);
  const adj = adjudicate(verdicts);
  const outPath = path.join(path.dirname(fp), `${f.slug || 'finding'}.refutation_report.json`);
  fs.writeFileSync(outPath, JSON.stringify({ slug: f.slug, ...adj, verdicts, at: f.commit ? `commit ${f.commit}` : undefined }, null, 2));

  console.log(`\n  ${adj.verdict === 'SURVIVED' ? '✅' : '⚠'} ${adj.verdict} — ${adj.refutedCount}/${adj.total} refuters found a killing guard`);
  for (const g of adj.killing_guards) if (g) console.log(`     - ${g.file}:${g.line} ${g.quote ? `(${g.quote})` : ''}`);
  console.log(`  report: ${path.relative(REPO, outPath)}\n`);
  process.exit(adj.verdict === 'SURVIVED' ? 0 : 3);
}

export { adjudicate, parseVerdict, buildRefuterPrompt, guardExistsInSource };
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
