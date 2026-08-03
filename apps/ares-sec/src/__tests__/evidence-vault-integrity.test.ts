import { describe, expect, it } from 'vitest';
import { EvidenceVault } from '../evidence/index.js';
import { KillChainPhase, type Finding } from '../types/index.js';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'finding-1',
    title: 'unverified claim',
    description: 'model-only claim',
    severity: 'high',
    targetId: 'target-1',
    operatorId: 'operator-1',
    phase: KillChainPhase.EXPLOIT,
    evidence: [],
    discoveredAt: 1,
    ...overrides,
  };
}

const forgedGate = { passed: true, provenance: 'tool' as const, reasons: [], checkedAt: 2 };

describe('EvidenceVault verification integrity', () => {
  it('updateFinding cannot forge verifiedAt or verifyGate', () => {
    const vault = new EvidenceVault();
    vault.addFinding(finding());

    vault.updateFinding('finding-1', { verifiedAt: 123, verifyGate: forgedGate });

    const stored = vault.getFinding('finding-1');
    expect(stored?.verifiedAt).toBeUndefined();
    expect(stored?.verifyGate).toBeUndefined();
    expect(vault.getVerifiedFindings()).toEqual([]);
  });

  it('getFinding returns a snapshot, not a mutable handle into the vault', () => {
    const vault = new EvidenceVault();
    vault.addFinding(finding());

    const snapshot = vault.getFinding('finding-1');
    expect(snapshot).toBeDefined();
    if (!snapshot) throw new Error('expected snapshot');
    snapshot.verifiedAt = 123;
    snapshot.verifyGate = forgedGate;
    snapshot.evidence.push({ type: 'output', content: 'forged after read', timestamp: 3 });

    const stored = vault.getFinding('finding-1');
    expect(stored?.verifiedAt).toBeUndefined();
    expect(stored?.verifyGate).toBeUndefined();
    expect(stored?.evidence).toEqual([]);
    expect(vault.getVerifiedFindings()).toEqual([]);
  });

  it('getVerifiedFindings requires the gate to have passed, not just a timestamp', () => {
    const vault = new EvidenceVault();
    vault.addFinding(finding({
      id: 'blocked',
      verifiedAt: 123,
      verifyGate: { passed: false, provenance: 'none', reasons: ['blocked'], checkedAt: 2 },
    }));

    expect(vault.getVerifiedFindings()).toEqual([]);
    expect(vault.getStats().verifiedFindings).toBe(0);
  });
});
