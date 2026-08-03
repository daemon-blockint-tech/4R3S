#!/usr/bin/env node
/**
 * target-rank — aim the hunter. The strongest strategic signal from the campaign:
 * the Critical and the Highs all came from UNDER-AUDITED, NETWORK-FACING,
 * MEMORY-UNSAFE VENDOR/DEVICE SDKs — while every mature/heavily-audited core stack
 * (mainstream middleware + crypto) came back hardened. This scores candidate targets
 * by those crit-yield features and ranks them, so the hunt spends its budget where
 * bugs actually are.
 *
 * Calibrated + self-tested on the campaign's feature/outcome vectors: the model must
 * rank the real hits above the real misses (identities held — see CAMPAIGN below).
 *
 * Target descriptor (JSON): { name, lang, network_facing, transport, vendor_sdk,
 *   parses_untrusted, audit_maturity: "low"|"medium"|"high", default_config_reachable,
 *   prior_cves }
 *
 * Usage:
 *   node scripts/target-rank.mjs --targets targets.json    # ranks a JSON array
 *   node scripts/target-rank.mjs --self-test
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MEM_UNSAFE = new Set(['c', 'c++', 'cpp', 'objective-c', 'rust-unsafe']);

function scoreTarget(t) {
  const r = []; let s = 0;
  const add = (n, why) => { s += n; r.push(`${n >= 0 ? '+' : ''}${n} ${why}`); };
  if (MEM_UNSAFE.has(String(t.lang || '').toLowerCase())) add(3, 'memory-unsafe language (where memory-safety crits live)');
  else add(-1, 'memory-safe language (memory-corruption crits unlikely)');
  if (t.network_facing) add(3, 'network-facing — AV:N (the vector that turns a High into a Crit)');
  else if (/serial|usb|device.?link|local/.test(String(t.transport || ''))) add(1, 'device-link/serial — AV:A (capped below Crit)');
  if (t.vendor_sdk) add(3, 'vendor/device/firmware SDK — under-audited relative to core libs');
  if (t.parses_untrusted) add(2, 'parses attacker-controlled wire/file input');
  if (t.default_config_reachable) add(1, 'reachable in default config (no security plugin needed → AC:L)');
  const m = String(t.audit_maturity || 'medium').toLowerCase();
  if (m === 'low') add(2, 'low audit maturity — novel bugs survive');
  else if (m === 'high') add(-3, 'heavily audited / hardened — low yield');
  const cves = Number(t.prior_cves);
  if (!Number.isNaN(cves)) { if (cves <= 2) add(1, 'few prior CVEs — under-scrutinized'); else if (cves > 20) add(-2, 'many prior CVEs — heavily scrutinized'); }
  return { name: t.name, score: s, reasons: r };
}

function rank(targets) { return targets.map(scoreTarget).sort((a, b) => b.score - a.score); }

// ── calibration / self-test set ──
// Feature vectors + hit/miss outcomes from a real robotics/crypto campaign. The
// target identities are held (coordinated disclosure); only the features + outcomes
// — which is what calibrates the scorer — are kept. Replace with your own targets.
const CAMPAIGN = [
  { name: 'T1 (network vendor SDK, C++)',      lang: 'c++', network_facing: true,  transport: 'udp',           vendor_sdk: true,  parses_untrusted: true, default_config_reachable: true,  audit_maturity: 'low',    prior_cves: 0,  _outcome: 'HIT — Critical' },
  { name: 'T2 (device-link vendor SDK, C++)',  lang: 'c++', network_facing: false, transport: 'serial/udp',    vendor_sdk: true,  parses_untrusted: true, default_config_reachable: true,  audit_maturity: 'low',    prior_cves: 1,  _outcome: 'HIT — High' },
  { name: 'T3 (network middleware SDK, C)',    lang: 'c',   network_facing: true,  transport: 'udp/serial',    vendor_sdk: true,  parses_untrusted: true, default_config_reachable: false, audit_maturity: 'medium', prior_cves: 1,  _outcome: 'HIT — High (config-gated)' },
  { name: 'T4 (network comms bus, C)',         lang: 'c',   network_facing: true,  transport: 'udp-multicast', vendor_sdk: false, parses_untrusted: true, default_config_reachable: true,  audit_maturity: 'low',    prior_cves: 0,  _outcome: 'HIT — Medium' },
  { name: 'T5 (network firmware, C++)',        lang: 'c++', network_facing: true,  transport: 'udp/radio',     vendor_sdk: true,  parses_untrusted: true, default_config_reachable: true,  audit_maturity: 'high',   prior_cves: 8,  _outcome: 'MISS — hardened' },
  { name: 'T6 (network core middleware, C)',   lang: 'c',   network_facing: true,  transport: 'udp',           vendor_sdk: false, parses_untrusted: true, default_config_reachable: true,  audit_maturity: 'high',   prior_cves: 6,  _outcome: 'MISS — guarded' },
  { name: 'T7 (network core middleware, C++)', lang: 'c++', network_facing: true,  transport: 'udp',           vendor_sdk: false, parses_untrusted: true, default_config_reachable: true,  audit_maturity: 'high',   prior_cves: 10, _outcome: 'MISS — bounded' },
  { name: 'T8 (memory-safe crypto lib)',       lang: 'js',  network_facing: false, transport: 'library',       vendor_sdk: false, parses_untrusted: true, default_config_reachable: true,  audit_maturity: 'high',   prior_cves: 6,  _outcome: 'MISS — availability-only' },
];

function selfTest() {
  let pass = 0, fail = 0; const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  const ranked = rank(CAMPAIGN);
  const pos = (n) => ranked.findIndex((x) => x.name === n);
  ok('the network vendor SDK (the Critical) ranks #1', /network vendor SDK/.test(ranked[0].name));
  ok('the memory-safe crypto lib ranks last', /memory-safe crypto/.test(ranked[ranked.length - 1].name));
  ok('the under-audited vendor SDKs outrank the hardened core middleware',
    Math.max(pos('T2 (device-link vendor SDK, C++)'), pos('T3 (network middleware SDK, C)')) < Math.min(pos('T6 (network core middleware, C)'), pos('T7 (network core middleware, C++)')));
  ok('network T1 outranks device-link T2 (the AV:N→Crit lever)', pos('T1 (network vendor SDK, C++)') < pos('T2 (device-link vendor SDK, C++)'));
  ok('hardened firmware ranks below the under-audited SDKs', pos('T5 (network firmware, C++)') > pos('T3 (network middleware SDK, C)'));
  console.log('\n  calibrated ranking (campaign hits vs misses):');
  for (const x of ranked) { const c = CAMPAIGN.find((t) => t.name === x.name); console.log(`    ${String(x.score).padStart(3)}  ${x.name.padEnd(30)} ${c._outcome}`); }
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  process.exit(fail === 0 ? 0 : 1);
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.includes('--self-test')) return selfTest();
  const i = argv.indexOf('--targets');
  if (i < 0) { console.error('usage: target-rank --targets <targets.json> | --self-test'); process.exit(2); }
  const targets = JSON.parse(fs.readFileSync(argv[i + 1], 'utf8'));
  const ranked = rank(Array.isArray(targets) ? targets : targets.targets || []);
  console.log('\n════════ target-rank (crit-yield priority) ════════\n');
  for (const x of ranked) { console.log(`  ${String(x.score).padStart(3)}  ${x.name}`); for (const why of x.reasons) console.log(`         ${why}`); console.log(''); }
}

export { scoreTarget, rank, CAMPAIGN };
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) main();
