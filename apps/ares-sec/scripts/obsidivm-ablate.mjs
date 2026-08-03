/**
 * ARES × OBSIDIVM — cross-generation ablation analysis.
 *
 * Tracks a proposals-ledger keyed by stable proposal id (target_id/finding_id).
 * After each generation the ledger gains:
 *   - whether the proposal's target/finding was DETECTED this gen
 *   - cumulative lift contribution (severity-weighted points gained since added)
 *   - regression count (gens where detection flipped detect→miss)
 *
 * Pruning:  proposals with 0 lift after `--prune-after` gens get marked
 *           "deadweight" and excluded from accumulator regeneration.
 *           Accumulator (`current.md`) is rebuilt from alive proposals only.
 *
 * Importable from obsidivm-evolve.mjs:
 *   import { runAblation, rebuildAccumulator, ablationLeaderboard } from './obsidivm-ablate.mjs';
 *
 * Also runnable standalone for analysis without re-running bench:
 *   node scripts/obsidivm-ablate.mjs report
 *   node scripts/obsidivm-ablate.mjs leaderboard
 *   node scripts/obsidivm-ablate.mjs prune --threshold 3
 */

import fs   from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const REPO       = path.resolve(__dirname, '..');
const EVO_DIR    = path.join(REPO, 'bench', 'obsidivm-evolution');

const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0.5 };

// ---------------------------------------------------------------------------
// proposals-ledger persistence
// ---------------------------------------------------------------------------

function ledgerPath() { return path.join(EVO_DIR, 'proposals-ledger.json'); }

export function loadProposalsLedger() {
  const p = ledgerPath();
  if (!fs.existsSync(p)) return { proposals: {} };
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); }
  catch { return { proposals: {} }; }
}

function saveProposalsLedger(ledger) {
  fs.mkdirSync(EVO_DIR, { recursive: true });
  fs.writeFileSync(ledgerPath(), JSON.stringify(ledger, null, 2));
}

function stableId(p) {
  // tactic-level identity: target × finding (one tactic per (target,finding) gap)
  const tid = p.miss?.target_id || p.target_id || 'unknown';
  const fid = p.miss?.finding_id || p.finding_id || 'unknown';
  return `${tid}::${fid}`;
}

// ---------------------------------------------------------------------------
// per-gen update — call after a generation's bench + accepted proposals are known
// ---------------------------------------------------------------------------

/**
 * @param {number} gen
 * @param {object} benchReport - obsidivm-bench JSON
 * @param {Array<object>} acceptedThisGen - newly-accepted proposals
 * @returns {object} updated ledger + per-proposal lift this gen
 */
export function updateProposalsLedger(gen, benchReport, acceptedThisGen) {
  const ledger = loadProposalsLedger();

  // detection map this gen: target/finding → bool
  const detected = new Map();
  for (const t of benchReport.targets || []) {
    if (!t.verdict) continue;
    for (const r of t.verdict.results || []) {
      detected.set(`${t.target}::${r.id}`, { hit: !!r.detected, severity: r.severity });
    }
  }

  // register any newly-accepted proposals
  for (const p of acceptedThisGen) {
    const id = stableId(p);
    if (!ledger.proposals[id]) {
      ledger.proposals[id] = {
        id,
        target_id: p.miss?.target_id,
        finding_id: p.miss?.finding_id,
        title: p.miss?.title || '',
        severity: p.miss?.severity || 'info',
        tactic: p.tactic,
        confidence: p.confidence,
        rationale: p.rationale || '',
        risk: p.risk || '',
        gen_added: gen,
        gen_pruned: null,
        history: [],         // [{gen, detected}]
        lift_total: 0,       // cumulative weighted points contribution
        last_state: null,    // 'detected' | 'missed' | null
        regressions: 0,      // count of detect → miss flips
        improvements: 0,     // count of miss → detect flips
      };
    }
  }

  const lifts = {};
  for (const id of Object.keys(ledger.proposals)) {
    const entry = ledger.proposals[id];
    if (entry.gen_pruned) continue;  // already dead-weight
    const detectionInfo = detected.get(id);
    if (!detectionInfo) continue;

    const now = detectionInfo.hit ? 'detected' : 'missed';
    entry.history.push({ gen, detected: detectionInfo.hit });

    if (entry.last_state) {
      const flipped = entry.last_state !== now;
      if (flipped) {
        const weight = SEVERITY_WEIGHT[detectionInfo.severity] || 1;
        if (now === 'detected') {
          entry.improvements++;
          entry.lift_total += weight;
          lifts[id] = (lifts[id] || 0) + weight;
        } else {
          entry.regressions++;
          entry.lift_total -= weight;
          lifts[id] = (lifts[id] || 0) - weight;
        }
      }
    } else {
      // first observation after adding → treat detected as initial credit
      if (now === 'detected') {
        const weight = SEVERITY_WEIGHT[detectionInfo.severity] || 1;
        entry.improvements++;
        entry.lift_total += weight;
        lifts[id] = (lifts[id] || 0) + weight;
      }
    }
    entry.last_state = now;
  }

  saveProposalsLedger(ledger);
  return { ledger, lifts };
}

// ---------------------------------------------------------------------------
// pruning
// ---------------------------------------------------------------------------

/**
 * Mark proposals "deadweight" when they have 0 lift after `pruneAfter` gens.
 * Returns list of newly-pruned ids.
 */
export function prune(currentGen, { pruneAfter = 3 } = {}) {
  const ledger = loadProposalsLedger();
  const pruned = [];
  for (const [id, entry] of Object.entries(ledger.proposals)) {
    if (entry.gen_pruned) continue;
    const age = currentGen - entry.gen_added + 1;
    if (age < pruneAfter) continue;
    if (entry.lift_total <= 0 && entry.improvements === 0) {
      entry.gen_pruned = currentGen;
      pruned.push(id);
    }
  }
  if (pruned.length) saveProposalsLedger(ledger);
  return pruned;
}

// ---------------------------------------------------------------------------
// accumulator rebuild — only alive, positive-lift proposals
// ---------------------------------------------------------------------------

export function rebuildAccumulator() {
  const ledger = loadProposalsLedger();
  const alive = Object.values(ledger.proposals)
    .filter(p => !p.gen_pruned)
    .sort((a, b) => (b.lift_total - a.lift_total) || (a.gen_added - b.gen_added));

  if (alive.length === 0) {
    fs.writeFileSync(path.join(EVO_DIR, 'current.md'), '');
    return { kept: 0, pruned: Object.values(ledger.proposals).filter(p => p.gen_pruned).length };
  }

  const lines = [
    '# ARES × OBSIDIVM — Learned Tactics (curated by ablation)',
    '',
    'These tactics survived ablation pruning. Sorted by lifetime lift contribution.',
    `Total alive: ${alive.length}.  Last rebuild: ${new Date().toISOString()}.`,
    '',
  ];
  for (const p of alive) {
    lines.push(`### ${p.target_id}/${p.finding_id} — ${p.title}  [lift +${p.lift_total}, conf ${Number(p.confidence).toFixed(2)}, gen ${String(p.gen_added).padStart(3, '0')}]`);
    lines.push('');
    lines.push(p.tactic.trim());
    lines.push('');
  }
  fs.writeFileSync(path.join(EVO_DIR, 'current.md'), lines.join('\n'));

  return { kept: alive.length, pruned: Object.values(ledger.proposals).filter(p => p.gen_pruned).length };
}

// ---------------------------------------------------------------------------
// leaderboard / report
// ---------------------------------------------------------------------------

export function ablationLeaderboard(limit = 20) {
  const ledger = loadProposalsLedger();
  const entries = Object.values(ledger.proposals);
  if (entries.length === 0) return '(no proposals in ledger)';

  const alive = entries.filter(p => !p.gen_pruned)
                       .sort((a, b) => b.lift_total - a.lift_total);
  const dead = entries.filter(p => p.gen_pruned);

  const lines = [];
  lines.push('  rank  lift  conf  age  flips  proposal');
  lines.push('  ' + '─'.repeat(70));
  alive.slice(0, limit).forEach((p, i) => {
    const age = p.history.length || (p.gen_pruned ? p.gen_pruned - p.gen_added : '?');
    const flips = `+${p.improvements}/-${p.regressions}`;
    lines.push(`  ${String(i + 1).padStart(4)}   ${String(p.lift_total).padStart(4)}  ${Number(p.confidence).toFixed(2)}  ${String(age).padStart(3)}  ${flips.padEnd(6)} ${p.target_id}/${p.finding_id} — ${p.title.slice(0, 40)}`);
  });
  if (dead.length) {
    lines.push('  ' + '─'.repeat(70));
    lines.push(`  ${dead.length} pruned (deadweight): ${dead.slice(0, 5).map(p => p.target_id + '/' + p.finding_id).join(', ')}${dead.length > 5 ? ', …' : ''}`);
  }
  return lines.join('\n');
}

export function ablationStats() {
  const ledger = loadProposalsLedger();
  const entries = Object.values(ledger.proposals);
  const alive = entries.filter(p => !p.gen_pruned);
  const dead  = entries.filter(p => p.gen_pruned);
  const totalLift = alive.reduce((s, p) => s + p.lift_total, 0);
  const topLift = alive.slice().sort((a, b) => b.lift_total - a.lift_total)[0];
  return {
    total: entries.length,
    alive: alive.length,
    pruned: dead.length,
    total_lift: totalLift,
    top_lift: topLift ? { id: topLift.id, lift: topLift.lift_total, title: topLift.title } : null,
  };
}

// ---------------------------------------------------------------------------
// run-everything convenience for evolve.mjs
// ---------------------------------------------------------------------------

/**
 * After a generation: update ledger, prune, rebuild accumulator.
 * Returns ablation summary.
 */
export function runAblation(gen, benchReport, acceptedThisGen, { pruneAfter = 3 } = {}) {
  const { lifts } = updateProposalsLedger(gen, benchReport, acceptedThisGen);
  const pruned = prune(gen, { pruneAfter });
  const rebuild = rebuildAccumulator();
  const stats = ablationStats();
  return { lifts, pruned, rebuild, stats };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function cli(argv) {
  const [cmd, ...rest] = argv;
  switch (cmd) {
    case undefined:
    case '-h':
    case '--help':
      console.log(`obsidivm-ablate CLI

  report           Show ablation stats (total, alive, pruned, top lift)
  leaderboard      Show top alive proposals by lift
  prune --threshold N    Manually run prune pass (dry-by-default unless --apply)
  rebuild          Rebuild current.md from alive proposals
`);
      return 0;
    case 'report': {
      const s = ablationStats();
      console.log(JSON.stringify(s, null, 2));
      return 0;
    }
    case 'leaderboard':
      console.log(ablationLeaderboard(50));
      return 0;
    case 'rebuild': {
      const r = rebuildAccumulator();
      console.log(`rebuilt current.md: kept=${r.kept} pruned=${r.pruned}`);
      return 0;
    }
    case 'prune': {
      const threshold = (() => {
        const i = rest.indexOf('--threshold');
        return i !== -1 ? parseInt(rest[i + 1], 10) : 3;
      })();
      const apply = rest.includes('--apply');
      if (!apply) {
        const ledger = loadProposalsLedger();
        const candidates = Object.values(ledger.proposals).filter(p =>
          !p.gen_pruned && p.history.length >= threshold && p.lift_total <= 0 && p.improvements === 0
        );
        console.log(`would prune ${candidates.length} proposals (dry-run; --apply to commit)`);
        candidates.forEach(p => console.log(`  ${p.id} — ${p.title}`));
      } else {
        const lastGen = Math.max(0, ...Object.values(loadProposalsLedger().proposals).flatMap(p => p.history.map(h => h.gen)));
        const pruned = prune(lastGen, { pruneAfter: threshold });
        rebuildAccumulator();
        console.log(`pruned ${pruned.length} proposals; accumulator rebuilt`);
      }
      return 0;
    }
    default:
      console.error(`unknown command: ${cmd}`);
      return 2;
  }
}

if (import.meta.url === `file://${process.argv[1]}` ||
    process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(cli(process.argv.slice(2)));
}
