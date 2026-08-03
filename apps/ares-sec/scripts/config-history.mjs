// config-history.mjs — append-only SCORED LEDGER of {squad config -> benchmark score}.
// A thin index over the numbers the harnesses already compute (it RECOMPUTES nothing). Every run
// appends a row; rankConfigs() aggregates repeat runs per config (mean strict + pooled Wilson CI +
// run-count) so the Admiral / an operator can see which squads win — but ONLY on the split the
// caller asks for, so a train-set winner is never mistaken for a proven generalization.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LEDGER = path.join(ROOT, 'bench', 'cve-zero', 'results', 'config-history.jsonl');

// stable hash of the squad SHAPE (class+count+effort, order-independent) + model + rounds
export function configHash({ squad, model, rounds }) {
  const norm = [...(squad || [])]
    .map((s) => ({ class: s.class, count: s.count || 1, effort: s.effort || null }))
    .sort((a, b) => a.class.localeCompare(b.class));
  return crypto.createHash('sha1')
    .update(JSON.stringify({ squad: norm, model: model || 'codex-default', rounds: rounds ?? null }))
    .digest('hex').slice(0, 12);
}

export function appendConfigRecord(rec) {
  const row = { ts: new Date().toISOString(), configHash: configHash(rec), ...rec };
  fs.mkdirSync(path.dirname(LEDGER), { recursive: true });
  fs.appendFileSync(LEDGER, JSON.stringify(row) + '\n');
  return row;
}

function readAll() {
  if (!fs.existsSync(LEDGER)) return [];
  return fs.readFileSync(LEDGER, 'utf8').split('\n').filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
}

function wilson(k, n) {
  if (!n) return [0, 0];
  const z = 1.96, p = k / n, d = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n), m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [Math.max(0, (c - m) / d), Math.min(1, (c + m) / d)];
}

// rank distinct configs by mean strict (then narrower CI, then fewer calls). Filter by split + family.
export function rankConfigs({ split, targetFamily } = {}) {
  let rows = readAll().filter((r) => r.valid !== false); // invalid/rate-limited non-runs never count toward a config's score
  if (split) rows = rows.filter((r) => r.split === split);
  if (targetFamily) rows = rows.filter((r) => r.targetFamily === targetFamily);
  const byHash = new Map();
  for (const r of rows) {
    const g = byHash.get(r.configHash) || { configHash: r.configHash, squad: r.squad, model: r.model, rounds: r.rounds, n: 0, strict: 0, lenient: 0, anyHit: 0, calls: [], precisionCaveat: r.precisionCaveat };
    g.n++; g.strict += r.strict ? 1 : 0; g.lenient += r.lenient ? 1 : 0; g.anyHit += r.anyHit ? 1 : 0;
    if (typeof r.calls === 'number') g.calls.push(r.calls);
    byHash.set(r.configHash, g);
  }
  const out = [...byHash.values()].map((g) => {
    const ci = wilson(g.strict, g.n);
    return { configHash: g.configHash, squad: g.squad, model: g.model, rounds: g.rounds, n: g.n,
      meanStrict: g.n ? g.strict / g.n : 0, ci: ci.map((x) => +x.toFixed(3)),
      meanCalls: g.calls.length ? +(g.calls.reduce((a, b) => a + b, 0) / g.calls.length).toFixed(1) : null,
      precisionCaveat: g.precisionCaveat };
  });
  out.sort((a, b) => (b.meanStrict - a.meanStrict) || ((a.ci[1] - a.ci[0]) - (b.ci[1] - b.ci[0])) || ((a.meanCalls ?? 1e9) - (b.meanCalls ?? 1e9)));
  return out;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const argv = process.argv.slice(2);
  const gv = (k) => { const i = argv.indexOf('--' + k); return i >= 0 ? argv[i + 1] : undefined; };
  if (argv.includes('--self-test')) {
    let pass = 0, fail = 0; const ok = (l, c) => (c ? (pass++, console.log('  ✅ ' + l)) : (fail++, console.log('  ❌ ' + l)));
    const h1 = configHash({ squad: [{ class: 'a', count: 1 }, { class: 'b', count: 2 }], model: 'm', rounds: 2 });
    const h2 = configHash({ squad: [{ class: 'b', count: 2 }, { class: 'a', count: 1 }], model: 'm', rounds: 2 });
    ok('configHash is order-independent', h1 === h2);
    ok('configHash differs on count change', h1 !== configHash({ squad: [{ class: 'a', count: 1 }, { class: 'b', count: 1 }], model: 'm', rounds: 2 }));
    ok('configHash differs on model change', h1 !== configHash({ squad: [{ class: 'a', count: 1 }, { class: 'b', count: 2 }], model: 'n', rounds: 2 }));
    console.log(`\n${fail === 0 ? '✅ ALL PASS' : '❌ ' + fail + ' FAILED'} — ${pass}/${pass + fail}\n`);
    process.exitCode = fail === 0 ? 0 : 1;
  } else {
    const ranked = rankConfigs({ split: gv('split'), targetFamily: gv('family') });
    console.log(`\nconfig-history ranking${gv('split') ? ` (split=${gv('split')})` : ''}${gv('family') ? ` (family=${gv('family')})` : ''} — ${ranked.length} distinct config(s):\n`);
    for (const r of ranked) console.log(`  ${r.configHash}  strict ${(r.meanStrict * 100).toFixed(0)}% (n=${r.n}, CI ${(r.ci[0] * 100).toFixed(0)}-${(r.ci[1] * 100).toFixed(0)}%)  calls~${r.meanCalls ?? '?'}  [${(r.squad || []).map((s) => s.class + 'x' + (s.count || 1)).join(' ')}]`);
    console.log(ranked.length ? '' : '  (empty ledger — no runs recorded yet)\n');
  }
}
