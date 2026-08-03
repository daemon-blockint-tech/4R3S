/**
 * Purpose-built post-ex drivers (metasploit, hydra). Pins the load-bearing safety contract:
 *  - each carries its riskTier (dangerous / credential) so the approval gate fences it.
 *  - a missing binary DEGRADES (does not throw).
 *  - the target is scope-checked AND dash-guarded before anything spawns.
 *  - metasploit refuses msf-command injection (;, newline, quotes) in module/options.
 *  - the happy path builds the expected argv; hydra caps its task rate.
 * All deps are injected fakes — no real msfconsole/hydra is spawned.
 */
import { describe, it, expect } from 'vitest';
import { createMetasploitTool, createHydraTool, buildPostExTools } from '../arsenal/post-ex.js';
import type { AdapterToolDeps, SubprocessResult } from '../arsenal/adapter-tools.js';
import type { ToolContext } from '../types/index.js';

function makeDeps(overrides: Partial<AdapterToolDeps> = {}): AdapterToolDeps & { spawns: Array<{ cmd: string; args: string[] }> } {
  const spawns: Array<{ cmd: string; args: string[] }> = [];
  return {
    spawns,
    isToolAvailable: async () => true,
    runSubprocess: async (cmd, args): Promise<SubprocessResult> => {
      spawns.push({ cmd, args });
      return { stdout: 'FAKE', stderr: '', exitCode: 0 };
    },
    ...overrides,
  };
}
const ctx = (parameters: Record<string, unknown>): ToolContext => ({ parameters });

describe('metasploit_module driver', () => {
  it('is a dangerous, approval-gated tool', () => {
    expect(createMetasploitTool(makeDeps()).riskTier).toBe('dangerous');
  });

  it('degrades (no throw) when msfconsole is absent', async () => {
    const deps = makeDeps({ isToolAvailable: async () => false });
    const res = await createMetasploitTool(deps).handler(ctx({ module: 'auxiliary/scanner/ssh/ssh_version', target: '10.0.0.5' }));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/not installed/);
    expect(deps.spawns).toHaveLength(0);
  });

  it('refuses an out-of-scope RHOSTS before spawning', async () => {
    const deps = makeDeps({ scopeOk: () => false });
    const res = await createMetasploitTool(deps).handler(ctx({ module: 'exploit/x', target: 'evil.example.com' }));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/SCOPE DENIED/);
    expect(deps.spawns).toHaveLength(0);
  });

  it('refuses msf-command injection in a module/option value', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const tool = createMetasploitTool(deps);
    const inj = await tool.handler(ctx({ module: 'exploit/x; sessions -K', target: '10.0.0.5' }));
    expect(inj.success).toBe(false);
    expect(inj.error).toMatch(/invalid module|msf-command metacharacters/); // caught by the module-path validator
    const inj2 = await tool.handler(ctx({ module: 'exploit/x', target: '10.0.0.5', options: { LHOST: '1.2.3.4\nexploit -j' } }));
    expect(inj2.success).toBe(false);
    expect(inj2.error).toMatch(/msf-command metacharacters/); // an option VALUE newline is caught by MSF_UNSAFE
    expect(deps.spawns).toHaveLength(0);
  });

  it('refuses a target-override via options (RHOSTS/RHOST/VHOST) — no out-of-scope escape', async () => {
    const deps = makeDeps({ scopeOk: () => true }); // the resolved target is in-scope
    const tool = createMetasploitTool(deps);
    const res = await tool.handler(ctx({ module: 'exploit/x', target: '10.0.0.5', options: { RHOSTS: '9.9.9.9' } }));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/target override refused/);
    expect(deps.spawns).toHaveLength(0);
  });

  it('refuses a whitespace-padded / space-bearing option key (RHOSTS-override injection escape)', async () => {
    const deps = makeDeps({ scopeOk: () => true }); // resolved target is in-scope
    const tool = createMetasploitTool(deps);
    // each of these keys would inject a second `set …` directive into the -x string if it slipped
    // past the exact-match target guard; the strict key validator must refuse them all.
    for (const key of ['RHOSTS ', ' rhosts', 'RHOSTS\t', 'RHOSTS 9.9.9.9', 'AutoRunScript multi/handler']) {
      const res = await tool.handler(ctx({ module: 'exploit/x', target: '10.0.0.5', options: { [key]: 'y' } }));
      expect(res.success, `key "${key}" must be refused`).toBe(false);
    }
    expect(deps.spawns).toHaveLength(0);
    // a clean option key still works
    const ok = await tool.handler(ctx({ module: 'exploit/x', target: '10.0.0.5', options: { RPORT: 8080 } }));
    expect(ok.success).toBe(true);
  });

  it('refuses a malformed // , scheme, or @ target (checked host != emitted RHOSTS)', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    // '8.8.8.8@10.0.0.5' scope-checks as 10.0.0.5 but msf would receive the raw @-value — refuse it
    for (const t of ['//evil.com', 'file:///etc/passwd', '8.8.8.8@10.0.0.5']) {
      const res = await createMetasploitTool(deps).handler(ctx({ module: 'exploit/x', target: t }));
      expect(res.success).toBe(false);
      expect(res.error).toMatch(/malformed target/);
    }
    expect(deps.spawns).toHaveLength(0);
  });

  it('builds the resource-command -x string on the happy path', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const res = await createMetasploitTool(deps).handler(
      ctx({ module: 'auxiliary/scanner/ssh/ssh_login', target: '10.0.0.5', options: { RPORT: 22 } }),
    );
    expect(res.success).toBe(true);
    expect(deps.spawns[0].cmd).toBe('msfconsole');
    const cmd = deps.spawns[0].args[deps.spawns[0].args.indexOf('-x') + 1];
    expect(cmd).toContain('use auxiliary/scanner/ssh/ssh_login');
    expect(cmd).toContain('set RHOSTS 10.0.0.5');
    expect(cmd).toContain('set RPORT 22');
    expect(cmd).toContain('run');
  });
});

describe('hydra_bruteforce driver', () => {
  it('is a credential, approval-gated tool', () => {
    expect(createHydraTool(makeDeps()).riskTier).toBe('credential');
  });

  it('degrades when hydra is absent', async () => {
    const deps = makeDeps({ isToolAvailable: async () => false });
    const res = await createHydraTool(deps).handler(ctx({ service: 'ssh', target: '10.0.0.5', user: 'root', password: 'x' }));
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/not installed/);
  });

  it('rejects a bogus service and option-looking credentials', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    const tool = createHydraTool(deps);
    expect((await tool.handler(ctx({ service: 'ssh; rm -rf', target: '10.0.0.5', user: 'a', password: 'b' }))).success).toBe(false);
    expect((await tool.handler(ctx({ service: 'ssh', target: '10.0.0.5', user: '-oN', password: 'b' }))).success).toBe(false);
    expect((await tool.handler(ctx({ service: 'ssh', target: '//evil.com', user: 'a', password: 'b' }))).success).toBe(false); // malformed target
    expect(deps.spawns).toHaveLength(0);
  });

  it('scope-denies the target and requires user+pass', async () => {
    expect((await createHydraTool(makeDeps({ scopeOk: () => false })).handler(ctx({ service: 'ssh', target: '8.8.8.8', user: 'a', password: 'b' }))).success).toBe(false);
    expect((await createHydraTool(makeDeps({ scopeOk: () => true })).handler(ctx({ service: 'ssh', target: '10.0.0.5' }))).error).toMatch(/user/);
  });

  it('builds argv and caps the task rate at 16', async () => {
    const deps = makeDeps({ scopeOk: () => true });
    await createHydraTool(deps).handler(ctx({ service: 'ssh', target: '10.0.0.5', userlist: '/u.txt', passlist: '/p.txt', tasks: 500 }));
    const argv = deps.spawns[0].args;
    expect(argv).toEqual(['-L', '/u.txt', '-P', '/p.txt', '-t', '16', '-f', 'ssh://10.0.0.5']);
  });
});

describe('buildPostExTools', () => {
  it('returns both drivers, both approval-gated', () => {
    const tools = buildPostExTools(makeDeps());
    expect(tools.map((t) => t.name).sort()).toEqual(['hydra_bruteforce', 'metasploit_module']);
    expect(tools.every((t) => t.riskTier === 'dangerous' || t.riskTier === 'credential')).toBe(true);
  });
});
