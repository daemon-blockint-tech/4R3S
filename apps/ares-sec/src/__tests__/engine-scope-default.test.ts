/**
 * SEC-3: the shipping engine (AresCommand) must boot with the egress scope gate
 * fail-closed-for-public, not fully open. Before this change, Arsenal.getScope() stayed null
 * (enforcement off) until the first target was added, so a networked tool could reach any public
 * host in that window. Now the engine seeds a deny-all-public scope at construction; loopback and
 * RFC-1918/lab ranges stay open (zero regression for local dev), and ARES_SCOPE_OPEN=1 restores
 * the old fully-unscoped behavior for a deliberate unscoped run. Pins: the default scope shape,
 * that a public-target call is refused before its handler runs, and that adding an authorized
 * target still admits it (existing behavior preserved).
 */
import { describe, it, expect, afterEach } from 'vitest';
import { AresCommand } from '../index.js';
import { Arsenal } from '../arsenal/index.js';
import type { CustomTool, ToolContext } from '../types/index.js';

const ctx = (parameters: Record<string, unknown>): ToolContext => ({ parameters });

function probe(name: string): CustomTool & { ran: () => boolean } {
  let ran = false;
  const tool: CustomTool = {
    name, description: 'x', category: 'web', parameters: [],
    handler: async () => { ran = true; return { success: true, output: 'DID_RUN' }; },
  };
  return Object.assign(tool, { ran: () => ran });
}

function mkCmd(): AresCommand {
  return new AresCommand({ name: 'Scope Op', llm: { provider: 'mock', model: 'mock-model' } });
}

describe('engine egress scope default (SEC-3)', () => {
  afterEach(() => {
    delete process.env.ARES_SCOPE_OPEN;
  });

  it('boots fail-closed-for-public: scope is deny-all-public, not null, before any target', () => {
    const cmd = mkCmd();
    expect(cmd.arsenal.getScope()).toEqual({ allowedHosts: [], allowLoopback: true, allowPrivate: true });
  });

  it('denies a public-target tool before the first target is added — handler never runs', async () => {
    const cmd = mkCmd();
    const t = probe('probe_public');
    cmd.arsenal.register(t);
    const res = await cmd.arsenal.execute('probe_public', ctx({ url: 'https://evil.com' }));
    expect(t.ran()).toBe(false);
    expect(res.success).toBe(false);
    expect(res.error).toMatch(/SCOPE DENIED/);
  });

  it('zero regression for local/lab: loopback + RFC-1918 targets still run pre-target', async () => {
    const cmd = mkCmd();
    const loop = probe('probe_loopback');
    cmd.arsenal.register(loop);
    expect((await cmd.arsenal.execute('probe_loopback', ctx({ host: '127.0.0.1' }))).success).toBe(true);
    expect(loop.ran()).toBe(true);

    const priv = probe('probe_private');
    cmd.arsenal.register(priv);
    expect((await cmd.arsenal.execute('probe_private', ctx({ target: '10.0.0.5' }))).success).toBe(true);
    expect(priv.ran()).toBe(true);
  });

  it('adding an authorized target admits that host (existing behavior preserved)', async () => {
    const cmd = mkCmd();
    cmd.targetEnv.addTarget({ name: 'ex', address: 'example.com', type: 'web_application', zone: 'external' });
    expect(cmd.arsenal.getScope()?.allowedHosts).toContain('example.com');

    const t = probe('probe_authorized');
    cmd.arsenal.register(t);
    const res = await cmd.arsenal.execute('probe_authorized', ctx({ url: 'https://example.com/x' }));
    expect(t.ran()).toBe(true);
    expect(res.success).toBe(true);
  });

  it('ARES_SCOPE_OPEN=1 opts out: scope stays null and public egress runs', async () => {
    process.env.ARES_SCOPE_OPEN = '1';
    const cmd = mkCmd();
    expect(cmd.arsenal.getScope()).toBeNull();

    const t = probe('probe_open');
    cmd.arsenal.register(t);
    const res = await cmd.arsenal.execute('probe_open', ctx({ url: 'https://evil.com' }));
    expect(t.ran()).toBe(true);
    expect(res.success).toBe(true);

    // the target:added path must also respect the opt-out (scope stays null, not just at boot)
    cmd.targetEnv.addTarget({ name: 'ex', address: 'example.com', type: 'web_application', zone: 'external' });
    expect(cmd.arsenal.getScope()).toBeNull();
  });

  it('bare Arsenal is unchanged: null scope = enforcement off', async () => {
    const ars = new Arsenal();
    const t = probe('probe_bare');
    ars.register(t);
    const res = await ars.execute('probe_bare', ctx({ url: 'https://evil.com' }));
    expect(t.ran()).toBe(true);
    expect(res.success).toBe(true);
  });
});
