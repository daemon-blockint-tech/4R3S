// classes.mjs — the SPECIALIST CLASS REGISTRY: the single source of truth for the swarm's
// specialists. Each class is a CoD-style loadout: a tuned focus prompt + optional curated
// toolkit + default reasoning-effort + the target families it owns. A run "squad" is a
// composition of classes (which x how many x effort), built MANUALLY (--squad) or by the
// Admiral (composeSquad). These are the HARDENED focus strings that took CVE-Zero 6->9 at full
// power; the shared anti-fabrication DOCTRINE lives in cli-swarm's specialistPrompt.
//
// Honesty note: composeSquad routes on CWE family via the SAME CWE_FAMILY map the scorer uses
// (imported, never duplicated) so a composed squad stays comparable to every other number.
import { fam } from './cve-zero-hunt.mjs';

// ── the classes ─────────────────────────────────────────────────────────────
// solo:true marks the generalist control (one agent, all classes) — excluded from the roster.
export const CLASSES = {
  injection: { id: 'injection', name: 'Injection', targetFamilies: ['inject', 'cmdi', 'sqli'],
    focus: 'command / code / eval / template / SQL injection — any untrusted input reaching an interpreter, shell, child_process, eval/Function, or query.' },
  'path-traversal': { id: 'path-traversal', name: 'Path traversal', targetFamilies: ['path'],
    focus: 'arbitrary file read/write/include via user-influenced paths — sendFile/static, fs.* sinks, require(), archive extraction, and the classic startsWith/normalize prefix bugs.' },
  'prototype-pollution': { id: 'prototype-pollution', name: 'Prototype pollution', targetFamilies: ['inject', 'deser'],
    focus: 'recursive merge/extend/clone and query/body/cookie/header parsing that writes attacker keys (__proto__/constructor/prototype), and the gadget that turns it into impact.' },
  'redos-dos': { id: 'redos-dos', name: 'ReDoS / resource DoS', targetFamilies: ['dos'],
    focus: 'catastrophic-backtracking regex on untrusted input; unbounded loops, recursion, allocations, or quadratic parsing reachable from a request.' },
  'ssrf-redirect': { id: 'ssrf-redirect', name: 'SSRF / open-redirect', targetFamilies: ['ssrf'],
    focus: 'ENUMERATE every outbound request (http.NewRequest / client.Do / net.Dial / url.Parse / *.get / fetch) AND every struct/DTO/form field named url/host/webhook/target/callback; for each, answer: is the host attacker-controlled, and does the response OR error return to the caller? Flag io.ReadAll(resp.Body) or a response body reflected to the caller as full-read SSRF / info-disclosure. Also open-redirect + host-header trust + parser-differential confusion.' },
  'authz-bypass': { id: 'authz-bypass', name: 'Authz / access-control', targetFamilies: ['authz', 'csrf', 'info'],
    focus: 'Work ENUMERATIVELY: build the route/endpoint inventory and, per endpoint, determine which principal reaches it (anonymous / guest / public-share / authenticated / which role). IMMEDIATELY flag any AllowAny / empty permission_classes / authentication removed on a network-reachable view AT ITS OWN LINE as a CWE-306 candidate. Verify every permission/role/identity write is guarded BEFORE it runs, and that sentinel-identity branches (== "anonymous"/"guest"/"admin", isAnonymous, RoleMember) cover ALL sensitive assignments in the function, not just the one they wrap. A docstring or comment that merely SAYS a token is required is NOT a check.' },
  deserialization: { id: 'deserialization', name: 'Deserialization / parse', targetFamilies: ['deser'],
    focus: 'cookie / JSON / multipart / content-type / config parsing, unsafe deserialization, type confusion, and length/bounds handling on parsed data (including duplicate-parameter / interpretation-conflict smuggling).' },
  'crypto-secrets': { id: 'crypto-secrets', name: 'Crypto / secrets', targetFamilies: ['tls'],
    focus: 'weak or predictable randomness for security tokens, non-constant-time comparison of secrets, signature-verification flaws, hardcoded or leaked credentials (and credential fields omitted from config redaction).' },
  'memory-safety': { id: 'memory-safety', name: 'Memory safety', targetFamilies: ['mem'],
    focus: 'OOB read/write, heap/stack buffer overflow, integer overflow leading to undersized allocation, use-after-free, unchecked length/offset/count/size fields when parsing UNTRUSTED binary input; trace attacker-controlled record sizes/offsets to memcpy/resize/indexing sinks.' },
  'supply-chain': { id: 'supply-chain', name: 'Supply-chain / privileged-action', targetFamilies: ['supply'],
    focus: 'a privileged action performed WITHOUT a confirmation prompt, allowlist, or explicit opt-in gate: install / download / dynamic-import / require-by-caller-supplied-name of a package, spawn, or auto-update (CWE-829-style arbitrary inclusion). Flag the ABSENCE of the confirmation even when installing "the package the user asked for" looks like intended behavior — name the exact decision site.' },
  // solo control — one generalist, all classes, one pass. Not part of the specialist roster.
  generalist: { id: 'generalist', name: 'Generalist', solo: true, targetFamilies: [],
    focus: 'ALL vulnerability classes in a single pass: injection (command/code/eval/template/SQL), path traversal / arbitrary file access, prototype pollution, ReDoS / resource DoS, SSRF / open-redirect, authz / access-control (enumerate endpoints + which principal reaches each; flag AllowAny / missing-auth at its own line; a docstring is not a check), unsafe deserialization / parsing / type confusion, crypto / secrets, memory safety, and supply-chain / privileged-action-without-confirmation. Map the whole shipped attack surface and report every exploitable bug you can substantiate.' },
};

// back-compat: some consumers (cli-swarm, pack/types) read `lens.key` — alias it to `id`.
for (const _c of Object.values(CLASSES)) _c.key = _c.id;

// ── accessors (LENSES/GENERALIST kept for back-compat with cli-swarm + pack/types.ts) ──
export const classList = () => Object.values(CLASSES).filter((c) => !c.solo);
export const getClass = (id) => CLASSES[id];
export const LENSES = classList();               // the 10 specialists
export const GENERALIST = CLASSES.generalist;

// ── squad presets: a squad is [{ class:id, count, effort? }] ──
export const SQUAD_PRESETS = {
  full: classList().map((c) => ({ class: c.id, count: 1 })),
  // a lean triage squad weighted to the classes that carry the most CVE-Zero families
  'cwe-triage': [
    { class: 'authz-bypass', count: 2 }, { class: 'ssrf-redirect', count: 2 },
    { class: 'injection', count: 1 }, { class: 'path-traversal', count: 1 },
    { class: 'deserialization', count: 1 }, { class: 'memory-safety', count: 1 },
  ],
};

// expand a squad into a flat per-agent run list; per-agent effort overrides class default overrides codex default
export function expandSquad(squad) {
  const out = [];
  for (const slot of (squad || [])) {
    const cls = getClass(slot.class);
    if (!cls || cls.solo) continue;
    const n = Math.max(1, slot.count || 1);
    for (let i = 0; i < n; i++) out.push({ class: cls, agentIndex: i, effort: slot.effort ?? cls.defaultEffort });
  }
  return out;
}

// parse a --squad arg: a preset name, or inline JSON [{class,count,effort}], else the full preset
export function parseSquadArg(str) {
  if (!str || str === 'true') return SQUAD_PRESETS.full;
  if (SQUAD_PRESETS[str]) return SQUAD_PRESETS[str];
  try { const j = JSON.parse(str); if (Array.isArray(j)) return j; } catch {}
  return SQUAD_PRESETS.full;
}

// ── the Admiral's rule-based auto-composer: target -> squad ──
// Matching classes get 2 agents; a small FIXED breadth budget of off-target classes get 1 each
// (so a composed squad can be CHEAPER-and-competitive vs full — otherwise ranking learns nothing).
// Unknown/unmapped target -> full preset (documented fallback; e.g. CVE families with no class).
const BREADTH_BUDGET = 3;
export function composeSquad(target) {
  const cwes = (target && target.cwes) || [];
  const families = [...new Set(cwes.map((c) => fam(c)))];
  const roster = classList();
  const matching = roster.filter((c) => (c.targetFamilies || []).some((f) => families.includes(f)));
  if (!matching.length) return { squad: SQUAD_PRESETS.full, reason: 'unknown-target -> full fallback', families };
  const off = roster.filter((c) => !matching.includes(c)).slice(0, BREADTH_BUDGET);
  const squad = [
    ...matching.map((c) => ({ class: c.id, count: 2 })),
    ...off.map((c) => ({ class: c.id, count: 1 })),
  ];
  return { squad, reason: `matched ${matching.map((c) => c.id).join('+')} on ${families.join(',')} (+${off.length} breadth)`, families };
}

// ── offline self-test ──
export function selfTest() {
  let pass = 0, fail = 0;
  const ok = (l, c) => (c ? (pass++, console.log(`  ✅ ${l}`)) : (fail++, console.log(`  ❌ ${l}`)));
  ok('10 specialist classes (roster excludes solo)', classList().length === 10);
  ok('every class has id + focus + targetFamilies', classList().every((c) => c.id && c.focus && Array.isArray(c.targetFamilies)));
  ok('generalist is solo + not in roster', getClass('generalist').solo === true && !classList().some((c) => c.id === 'generalist'));
  ok('LENSES back-compat = the 10 specialists', LENSES.length === 10 && LENSES[0].key === LENSES[0].id && !!LENSES[0].id);
  ok('supply-chain class present (recovers CWE-829)', !!getClass('supply-chain') && getClass('supply-chain').targetFamilies.includes('supply'));
  ok('presets expand to a run list', expandSquad(SQUAD_PRESETS.full).length === 10 && expandSquad(SQUAD_PRESETS['cwe-triage']).length === 8);
  ok('parseSquadArg: preset name', parseSquadArg('cwe-triage') === SQUAD_PRESETS['cwe-triage']);
  ok('parseSquadArg: inline JSON', parseSquadArg('[{"class":"ssrf-redirect","count":3}]')[0].class === 'ssrf-redirect');
  ok('expandSquad honors count + effort override', (() => { const e = expandSquad([{ class: 'authz-bypass', count: 2, effort: 'xhigh' }]); return e.length === 2 && e[0].effort === 'xhigh' && e[0].class.id === 'authz-bypass'; })());
  const ssrf = composeSquad({ cwes: ['CWE-918'] });
  ok('composeSquad: SSRF target -> ssrf-redirect x2 + breadth, cheaper than full', ssrf.squad.find((s) => s.class === 'ssrf-redirect')?.count === 2 && expandSquad(ssrf.squad).length < 10);
  const authz = composeSquad({ cwes: ['CWE-306', 'CWE-918'] });
  ok('composeSquad: authz+ssrf target matches both classes', authz.squad.some((s) => s.class === 'authz-bypass') && authz.squad.some((s) => s.class === 'ssrf-redirect'));
  const supply = composeSquad({ cwes: ['CWE-829'] });
  ok('composeSquad: CWE-829 -> supply-chain class', supply.squad.find((s) => s.class === 'supply-chain')?.count === 2);
  const info = composeSquad({ cwes: ['CWE-200'] });
  ok('composeSquad: CWE-200 (info) -> authz class', info.squad.find((s) => s.class === 'authz-bypass')?.count === 2);
  const unknown = composeSquad({ cwes: ['CWE-79'] }); // xss: no class -> full fallback
  ok('composeSquad: unmapped target -> full fallback', unknown.squad === SQUAD_PRESETS.full);
  console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass}/${pass + fail}\n`);
  return fail === 0;
}

import { fileURLToPath } from 'node:url';
import path from 'node:path';
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain && process.argv.includes('--self-test')) { process.exitCode = selfTest() ? 0 : 1; }
