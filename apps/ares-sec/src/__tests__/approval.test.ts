/**
 * Capability approval + spicy-action warning gate. Pins the safety contract:
 *  - ungated tools pass straight through; gated (intrusive/credential/dangerous) do not.
 *  - FAIL-SAFE: gated + no approver + not pre-approved → DENIED (unattended runs don't self-fire).
 *  - "approve once, then free": the interactive approver is asked ONCE per tool, then it runs free.
 *  - pre-authorization allowlist runs free (headless).
 *  - spicy actions fire a NON-BLOCKING warning every time an approved call runs; everything audited.
 */
import { describe, it, expect, vi } from 'vitest';
import {
  ApprovalController,
  isGatedRisk,
  isSpicyRisk,
  type ApprovalRequest,
  type RiskTier,
} from '../arsenal/approval.js';

const req = (over: Partial<ApprovalRequest> = {}): ApprovalRequest => ({
  tool: 'metasploit',
  risk: 'dangerous',
  operator: 'exploit-dev',
  target: '10.0.0.5',
  action: 'metasploit exploit/x → 10.0.0.5',
  ...over,
});

describe('risk classification', () => {
  it('gates only intrusive / credential / dangerous', () => {
    const gated: RiskTier[] = ['intrusive', 'credential', 'dangerous'];
    const open: RiskTier[] = ['local_read', 'passive', 'active'];
    for (const r of gated) expect(isGatedRisk(r)).toBe(true);
    for (const r of open) expect(isGatedRisk(r)).toBe(false);
    expect(isGatedRisk(undefined)).toBe(false);
  });
  it('marks credential + dangerous as spicy (loud-warn), not intrusive', () => {
    expect(isSpicyRisk('dangerous')).toBe(true);
    expect(isSpicyRisk('credential')).toBe(true);
    expect(isSpicyRisk('intrusive')).toBe(false);
    expect(isSpicyRisk('active')).toBe(false);
  });
});

describe('ApprovalController.gate', () => {
  it('lets an ungated (active) tool straight through, no record', async () => {
    const c = new ApprovalController();
    const d = await c.gate(req({ tool: 'nmap', risk: 'active' }));
    expect(d.allowed).toBe(true);
    expect(c.getAudit()).toHaveLength(0);
  });

  it('FAIL-SAFE: a gated tool with no approver and no allowlist is DENIED', async () => {
    const c = new ApprovalController(); // nothing wired
    const d = await c.gate(req());
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/not authorized/);
    expect(c.getAudit()[0]?.outcome).toBe('denied-no-approver');
  });

  it('pre-authorization allowlist runs free (headless), and audits', async () => {
    const c = new ApprovalController({ preApprovedTools: ['metasploit', 'hydra'] });
    const d = await c.gate(req());
    expect(d.allowed).toBe(true);
    expect(c.getAudit()[0]?.outcome).toBe('allowed-preapproved');
    // a tool NOT on the list is still denied
    expect((await c.gate(req({ tool: 'sqlmap', risk: 'intrusive' }))).allowed).toBe(false);
  });

  it('interactive: approve ONCE, then free — the approver is asked exactly one time', async () => {
    const requestApproval = vi.fn(async () => true);
    const c = new ApprovalController({ requestApproval });
    expect((await c.gate(req())).allowed).toBe(true); // asks, approves
    expect((await c.gate(req())).allowed).toBe(true); // free — no second ask
    expect((await c.gate(req())).allowed).toBe(true);
    expect(requestApproval).toHaveBeenCalledTimes(1);
    expect(c.isApproved('metasploit')).toBe(true);
    expect(c.getAudit().map((r) => r.outcome)).toEqual([
      'allowed-interactive',
      'allowed-preapproved',
      'allowed-preapproved',
    ]);
  });

  it('interactive decline denies and does NOT approve the tool', async () => {
    const requestApproval = vi.fn(async () => false);
    const c = new ApprovalController({ requestApproval });
    const d = await c.gate(req());
    expect(d.allowed).toBe(false);
    expect(d.reason).toMatch(/declined/);
    expect(c.isApproved('metasploit')).toBe(false);
    expect(c.getAudit()[0]?.outcome).toBe('denied-declined');
  });

  it('spicy actions fire a NON-BLOCKING warning every allowed run; ungated-but-approved does not', async () => {
    const onWarning = vi.fn();
    const c = new ApprovalController({ preApprovedTools: ['metasploit', 'sqlmap'], onWarning });
    await c.gate(req()); // dangerous → spicy → warns
    await c.gate(req()); // still warns on every run
    await c.gate(req({ tool: 'sqlmap', risk: 'intrusive' })); // gated but NOT spicy → no warn
    expect(onWarning).toHaveBeenCalledTimes(2);
    expect(onWarning.mock.calls[0][0].tool).toBe('metasploit');
    // the warning never blocks — all three calls were allowed
    expect(c.getAudit().every((r) => r.outcome.startsWith('allowed'))).toBe(true);
  });

  it('audit trail is a defensive copy carrying who/what/target/outcome/spicy/time', async () => {
    const c = new ApprovalController({ preApprovedTools: ['hydra'], now: () => 1234 });
    await c.gate(req({ tool: 'hydra', risk: 'credential', action: 'hydra ssh 10.0.0.5' }));
    const audit = c.getAudit();
    expect(audit[0]).toMatchObject({
      tool: 'hydra',
      risk: 'credential',
      operator: 'exploit-dev',
      spicy: true,
      outcome: 'allowed-preapproved',
      at: 1234,
    });
    audit[0].tool = 'MUTATED';
    expect(c.getAudit()[0].tool).toBe('hydra'); // internal trail untouched
  });
});
