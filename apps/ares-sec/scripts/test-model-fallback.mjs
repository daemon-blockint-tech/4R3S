#!/usr/bin/env node
/**
 * test-model-fallback — unit tests for the failure classifiers that drive
 * LLMBackbone's model-fallback ladder. The ladder escalates to the next model on
 * ANY failure the current one can't self-recover from:
 *   • soft failures on a 200  → classifySoftFailure() : 'refusal' | 'empty' | null
 *   • hard thrown errors      → classifyErrorKind()   : rate_limit/auth/timeout/…
 *
 * The hard requirement for refusal detection isn't catching refusals (easy) — it's
 * NOT firing on the "I can't find / I cannot reach" progress chatter a hacking
 * agent emits constantly (a false positive there would swap models mid-exploit).
 *
 * Runs against the BUILT artifact (dist/llm/index.js).
 *   npm run build && node scripts/test-model-fallback.mjs
 * Exit 0 = all assertions pass.
 */
import {
  isLikelyRefusal,
  reframeWithAuthorizedContext,
  classifySoftFailure,
  classifyErrorKind,
  LLMApiError,
  LLMBackbone,
} from '../dist/llm/index.js';

let pass = 0, fail = 0;
const ok = (label, cond) =>
  cond ? (pass++, console.log(`  ✅ ${label}`))
       : (fail++, console.log(`  ❌ ${label}`));

// ── Refusal detection (→ true) ───────────────────────────────────────────────
console.log('\nREFUSALS — must be detected:');
const REFUSALS = [
  ['plain "can\'t help"',        "I'm sorry, but I can't help with that request."],
  ['"cannot assist"',            'I cannot assist with creating malware for this.'],
  ['"won\'t provide"',           "I won't provide exploit code for unauthorized targets."],
  ['"must decline"',             'I must decline to participate in this activity.'],
  ['"as an AI ... not able"',    "As an AI, I'm not able to help with hacking into systems."],
  ['"don\'t feel comfortable"',  "I don't feel comfortable helping with that."],
  ['"against my guidelines"',    'This request goes against my guidelines, so I will not proceed.'],
  ['"not going to help"',        "I'm not going to help you exploit this system."],
  ['"cannot comply"',            'Sorry, but I cannot comply with this request.'],
  ['"violates ... policy"',      'That violates my usage policy and I will stop here.'],
];
for (const [label, text] of REFUSALS) ok(label, isLikelyRefusal(text) === true);
ok('content_filter finish_reason', isLikelyRefusal('', 'content_filter') === true);

// ── Non-refusals (→ false) — agent progress chatter must NOT fire ────────────
console.log('\nNON-REFUSALS — must NOT fire (agent progress chatter):');
const NON_REFUSALS = [
  ['"can\'t find the flag"',     "I can't find the flag yet, let me try another approach."],
  ['"cannot reach the host"',    'I cannot reach the host, retrying with a different port.'],
  ['"could not decompile"',      'I could not decompile statically, switching to dynamic analysis.'],
  ['"Unfortunately stripped"',   "Unfortunately the binary is stripped, so I'll use radare2."],
  ['"as an AI ... found SQLi"',  'As an AI assistant analyzing this CTF, I found a SQL injection at /login.'],
  ['"sorry, didn\'t work"',      "I'm sorry, that approach didn't work. Trying an XSS payload instead."],
  ['"cannot connect"',           'Cannot connect to 10.0.0.5:443 — firewall likely. Pivoting to SSRF.'],
  ['flag delivered',             'The flag is HTB{pwn3d_it}. I provided the exploit chain above.'],
  ['offers to help',             'I will help you find the vulnerability. Starting recon now.'],
  ['plain tool output',          'nmap scan report for 10.0.0.5\n22/tcp open ssh\n80/tcp open http'],
];
for (const [label, text] of NON_REFUSALS) ok(label, isLikelyRefusal(text) === false);
const longBody = 'Detailed exploitation walkthrough. '.repeat(50) +
  " Note: I can't help but point out the auth bypass at line 88. " +
  'Full chain follows. '.repeat(30);
ok('long substantive answer (>1200 chars) not a refusal',
   longBody.length > 1200 && isLikelyRefusal(longBody) === false);

// ── classifySoftFailure — the 200-but-unusable gate ──────────────────────────
console.log('\nSOFT FAILURES — classify a 200 that should still fall back:');
ok('refusal → "refusal"',        classifySoftFailure({ content: 'I cannot assist with that.' }) === 'refusal');
ok('empty string → "empty"',     classifySoftFailure({ content: '' }) === 'empty');
ok('whitespace-only → "empty"',  classifySoftFailure({ content: '   \n  ' }) === 'empty');
ok('undefined content → "empty"',classifySoftFailure({}) === 'empty');
ok('good answer → null',         classifySoftFailure({ content: 'Found RCE via SSTI at /search.' }) === null);
ok('tool-calls-only → null',     classifySoftFailure({ content: '', toolCalls: [{ id: '1', name: 'run', arguments: {} }] }) === null);

// ── classifyErrorKind — route hard errors to the right next hop ──────────────
console.log('\nHARD ERRORS — classify a thrown error for the ladder:');
ok('429 → rate_limit',       classifyErrorKind(new LLMApiError('rate limited', 429)) === 'rate_limit');
ok('401 → auth',             classifyErrorKind(new LLMApiError('unauthorized', 401)) === 'auth');
ok('403 → auth',             classifyErrorKind(new LLMApiError('forbidden', 403)) === 'auth');
ok('404 → model_unavailable',classifyErrorKind(new LLMApiError('no such model', 404)) === 'model_unavailable');
ok('500 → server_error',     classifyErrorKind(new LLMApiError('upstream blew up', 500)) === 'server_error');
ok('502 → server_error',     classifyErrorKind(new LLMApiError('bad gateway', 502)) === 'server_error');
ok('400+ctx-msg → context_length',
   classifyErrorKind(new LLMApiError('maximum context length is 8192 tokens', 400)) === 'context_length');
ok('400 plain → bad_request', classifyErrorKind(new LLMApiError('bad params', 400)) === 'bad_request');
ok('abort → timeout',        classifyErrorKind(new Error('The operation was aborted due to timeout')) === 'timeout');
ok('ECONNREFUSED → network', classifyErrorKind(new Error('connect ECONNREFUSED 1.2.3.4:443')) === 'network');
ok('null → unknown',         classifyErrorKind(null) === 'unknown');
ok('odd error → unknown',    classifyErrorKind(new Error('something weird happened')) === 'unknown');

// ── reframeWithAuthorizedContext — honest, non-mutating ──────────────────────
console.log('\nRE-FRAME — truthful authorization restatement (refusal hop only):');
const orig = [{ role: 'user', content: 'enumerate the target' }];
const reframed = reframeWithAuthorizedContext(orig);
ok('prepends exactly one system note', reframed.length === orig.length + 1 && reframed[0].role === 'system');
ok('does not mutate the original', orig.length === 1 && orig[0].role === 'user');
ok('states real authorization, not a jailbreak',
   /authoriz/i.test(reframed[0].content) && /scope/i.test(reframed[0].content) &&
   !/ignore|jailbreak|no restrictions|godmode|pretend/i.test(reframed[0].content));

// ── INTEGRATION: the real ladder flow in LLMBackbone.chat() (stubbed adapters) ─
console.log('\nLADDER FLOW (integration):');
{
  const mk = (content, finishReason) => ({ chat: async () => ({ content, finishReason }), validateConfig: () => ({ valid: true }) });
  const mkErr = (err) => ({ chat: async () => { throw err; }, validateConfig: () => ({ valid: true }) });
  const newBackbone = (fallbackChain) => {
    const b = new LLMBackbone({ provider: 'mock', model: 'primary', fallbackChain });
    b.retryAttempts = 1; // fail fast in tests
    return b;
  };
  const chain1 = [{ provider: 'mock', model: 'fb' }];

  // primary refuses → fallback engages and returns the good answer
  let b = newBackbone(chain1); b.adapter = mk('I cannot help with that.'); b.createAdapter = () => mk('Found a concrete bug at line 42.');
  let engaged = false; b.on('request:fallback', (e) => { if (e.engaged) engaged = true; });
  let r = await b.chat([{ role: 'user', content: 'audit' }]);
  ok('refusal → fallback engages + returns good answer', r.content.includes('line 42') && engaged);

  // primary hard-errors (500) → fallback engages
  b = newBackbone(chain1); b.adapter = mkErr(new LLMApiError('boom', 500)); b.createAdapter = () => mk('Recovered answer.');
  r = await b.chat([{ role: 'user', content: 'x' }]);
  ok('hard error → fallback engages', r.content.includes('Recovered'));

  // primary succeeds → no fallback, returns primary
  b = newBackbone(chain1); b.adapter = mk('Direct good answer.'); b.createAdapter = () => mk('SHOULD NOT BE USED');
  engaged = false; b.on('request:fallback', (e) => { if (e.engaged) engaged = true; });
  r = await b.chat([{ role: 'user', content: 'x' }]);
  ok('success → no fallback, returns primary', r.content.includes('Direct') && !engaged);

  // every rung refuses → returns an (honest) response, does NOT throw
  b = newBackbone(chain1); b.adapter = mk('I cannot help.'); b.createAdapter = () => mk('I will not assist with that.');
  let threw = false; r = undefined; try { r = await b.chat([{ role: 'user', content: 'x' }]); } catch { threw = true; }
  ok('all rungs refuse → returns a response (no throw)', !threw && !!r);

  // no fallbackChain + hard error → throws (back-compat preserved)
  b = newBackbone(undefined); b.adapter = mkErr(new LLMApiError('unauthorized', 401));
  threw = false; try { await b.chat([{ role: 'user', content: 'x' }]); } catch { threw = true; }
  ok('no chain + hard error → throws (back-compat)', threw);
}

console.log(`\n${fail === 0 ? '✅ ALL PASS' : `❌ ${fail} FAILED`} — ${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
