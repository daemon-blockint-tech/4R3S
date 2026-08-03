/**
 * ARES Evidence Vault
 *
 * Manages findings, credentials, and evidence chain of custody.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import type {
  Finding,
  Credential,
  Evidence,
  Severity,
  Vulnerability,
} from '../types/index.js';
import { gateLiveFinding } from './gate.js';

// =============================================================================
// CREDENTIAL REDACTION — secrets NEVER leave the process in an API/LLM output
// =============================================================================

/** A credential shaped for output: the raw `secret` is stripped, replaced by a boolean
 *  flag that it was captured. Mirrors the repo's redaction posture (secrets are summarized,
 *  never copied into responses/prompts). */
export type RedactedCredential = Omit<Credential, 'secret'> & { secretCaptured: boolean };

/** Strip the raw secret from a credential for any outward-facing surface (API responses,
 *  reports). Keeps all non-sensitive metadata + a `secretCaptured` flag; never the value. */
export function redactCredential(c: Credential): RedactedCredential {
  const { secret, ...rest } = c;
  return { ...rest, secretCaptured: Boolean(secret) };
}

// =============================================================================
// EVENTS
// =============================================================================

export interface EvidenceVaultEvents {
  'finding:added': Finding;
  'finding:updated': Finding;
  'finding:verified': Finding;
  'finding:gate-blocked': Finding;
  'credential:added': Credential;
  'credential:validated': Credential;
  'evidence:added': { findingId: string; evidence: Evidence };
}

// =============================================================================
// SEVERITY SCORING
// =============================================================================

export const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 10,
  high: 7.5,
  medium: 5,
  low: 2.5,
  info: 0,
};

export function cvssToSeverity(cvss: number): Severity {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  if (cvss >= 0.1) return 'low';
  return 'info';
}

function cloneEvidence(evidence: Evidence): Evidence {
  return {
    ...evidence,
    metadata: evidence.metadata ? { ...evidence.metadata } : undefined,
  };
}

function cloneFinding(finding: Finding): Finding {
  return {
    ...finding,
    cve: finding.cve ? [...finding.cve] : undefined,
    cwe: finding.cwe ? [...finding.cwe] : undefined,
    references: finding.references ? [...finding.references] : undefined,
    evidence: Array.isArray(finding.evidence) ? finding.evidence.map(cloneEvidence) : [],
    verifyGate: finding.verifyGate
      ? { ...finding.verifyGate, reasons: [...finding.verifyGate.reasons] }
      : undefined,
  };
}

function hasPassedVerificationGate(finding: Finding): boolean {
  return finding.verifiedAt !== undefined && finding.verifyGate?.passed === true;
}

// =============================================================================
// EVIDENCE VAULT
// =============================================================================

export class EvidenceVault extends EventEmitter<EvidenceVaultEvents> {
  private findings: Map<string, Finding> = new Map();
  private credentials: Map<string, Credential> = new Map();

  /**
   * Add a finding
   */
  addFinding(finding: Finding): Finding {
    if (!finding.id) {
      finding.id = randomUUID();
    }
    const stored = cloneFinding(finding);
    this.findings.set(stored.id, stored);
    this.emit('finding:added', cloneFinding(stored));
    return cloneFinding(stored);
  }

  /**
   * Update a finding
   */
  updateFinding(findingId: string, updates: Partial<Finding>): Finding | undefined {
    const finding = this.findings.get(findingId);
    if (finding) {
      const sanitized: Partial<Finding> = { ...updates };
      // Verification state is gate-owned. Callers may update finding metadata,
      // evidence, remediation, etc., but cannot self-stamp a finding as verified.
      delete sanitized.verifiedAt;
      delete sanitized.verifyGate;
      if (sanitized.evidence) sanitized.evidence = sanitized.evidence.map(cloneEvidence);
      if (sanitized.cve) sanitized.cve = [...sanitized.cve];
      if (sanitized.cwe) sanitized.cwe = [...sanitized.cwe];
      if (sanitized.references) sanitized.references = [...sanitized.references];
      Object.assign(finding, sanitized);
      this.emit('finding:updated', cloneFinding(finding));
    }
    return finding ? cloneFinding(finding) : undefined;
  }

  /**
   * Verify a finding — through the honesty gate. A finding is marked verified ONLY
   * if it passes the live verification gate (real tool-output provenance). Otherwise
   * it is left UNVERIFIED with the gate's reasons recorded — the gate is the door.
   */
  verifyFinding(findingId: string): Finding | undefined {
    const finding = this.findings.get(findingId);
    if (!finding) return finding;
    const gate = gateLiveFinding(finding);
    finding.verifyGate = { passed: gate.passed, provenance: gate.provenance, reasons: gate.reasons, checkedAt: gate.checkedAt };
    if (gate.passed) {
      finding.verifiedAt = Date.now();
      this.emit('finding:verified', cloneFinding(finding));
    } else {
      // refuse to stamp verified on a finding the gate could not back
      delete finding.verifiedAt;
      this.emit('finding:gate-blocked', cloneFinding(finding));
    }
    return cloneFinding(finding);
  }

  /**
   * Add evidence to a finding
   */
  addEvidence(findingId: string, evidence: Evidence): Finding | undefined {
    const finding = this.findings.get(findingId);
    if (finding) {
      const storedEvidence = cloneEvidence(evidence);
      finding.evidence.push(storedEvidence);
      this.emit('evidence:added', { findingId, evidence: cloneEvidence(storedEvidence) });
    }
    return finding ? cloneFinding(finding) : undefined;
  }

  /**
   * Get a finding by ID
   */
  getFinding(findingId: string): Finding | undefined {
    const finding = this.findings.get(findingId);
    return finding ? cloneFinding(finding) : undefined;
  }

  /**
   * Get all findings
   */
  getAllFindings(): Finding[] {
    return Array.from(this.findings.values()).map(cloneFinding);
  }

  /**
   * Get findings by severity
   */
  getFindingsBySeverity(severity: Severity): Finding[] {
    return this.getAllFindings().filter(f => f.severity === severity);
  }

  /**
   * Get findings by target
   */
  getFindingsByTarget(targetId: string): Finding[] {
    return this.getAllFindings().filter(f => f.targetId === targetId);
  }

  /**
   * Get findings by operator
   */
  getFindingsByOperator(operatorId: string): Finding[] {
    return this.getAllFindings().filter(f => f.operatorId === operatorId);
  }

  /**
   * Get verified findings
   */
  getVerifiedFindings(): Finding[] {
    return Array.from(this.findings.values()).filter(hasPassedVerificationGate).map(cloneFinding);
  }

  /**
   * Add a credential
   */
  addCredential(credential: Credential): Credential {
    if (!credential.id) {
      credential.id = randomUUID();
    }
    this.credentials.set(credential.id, credential);
    this.emit('credential:added', credential);
    return credential;
  }

  /**
   * Validate a credential
   */
  validateCredential(credentialId: string): Credential | undefined {
    const credential = this.credentials.get(credentialId);
    if (credential) {
      credential.validatedAt = Date.now();
      this.emit('credential:validated', credential);
    }
    return credential;
  }

  /**
   * Get a credential by ID
   */
  getCredential(credentialId: string): Credential | undefined {
    return this.credentials.get(credentialId);
  }

  /**
   * Get all credentials
   */
  getAllCredentials(): Credential[] {
    return Array.from(this.credentials.values());
  }

  /**
   * Get credentials by type
   */
  getCredentialsByType(type: Credential['type']): Credential[] {
    return this.getAllCredentials().filter(c => c.type === type);
  }

  /**
   * Get credentials by target
   */
  getCredentialsByTarget(targetId: string): Credential[] {
    return this.getAllCredentials().filter(c => c.targetId === targetId);
  }

  /**
   * Get vault statistics
   */
  getStats(): {
    totalFindings: number;
    verifiedFindings: number;
    bySeverity: Record<Severity, number>;
    totalCredentials: number;
    validatedCredentials: number;
    riskScore: number;
  } {
    const findings = Array.from(this.findings.values());
    const credentials = this.getAllCredentials();

    const bySeverity: Record<Severity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    let riskScore = 0;
    for (const finding of findings) {
      bySeverity[finding.severity]++;
      riskScore += SEVERITY_SCORES[finding.severity];
    }

    return {
      totalFindings: findings.length,
      verifiedFindings: findings.filter(hasPassedVerificationGate).length,
      bySeverity,
      totalCredentials: credentials.length,
      validatedCredentials: credentials.filter(c => c.validatedAt !== undefined).length,
      riskScore,
    };
  }

  /**
   * Export findings to JSON
   */
  exportFindings(): string {
    return JSON.stringify(this.getAllFindings(), null, 2);
  }

  /**
   * Clear the vault
   */
  clear(): void {
    this.findings.clear();
    this.credentials.clear();
  }
}

// =============================================================================
// FINDING FACTORIES
// =============================================================================

export function createFindingFromVuln(
  vuln: Vulnerability,
  targetId: string,
  operatorId: string,
  phase: Finding['phase']
): Finding {
  return {
    id: randomUUID(),
    title: vuln.name,
    description: vuln.description,
    severity: vuln.severity,
    targetId,
    operatorId,
    phase,
    cvss: vuln.cvss,
    cve: vuln.cve,
    cwe: vuln.cwe,
    evidence: [],
    references: vuln.references,
    discoveredAt: Date.now(),
  };
}

export function createMisconfigFinding(
  title: string,
  description: string,
  severity: Severity,
  targetId: string,
  operatorId: string,
  phase: Finding['phase'],
  evidence?: Evidence[]
): Finding {
  return {
    id: randomUUID(),
    title,
    description,
    severity,
    targetId,
    operatorId,
    phase,
    evidence: evidence || [],
    discoveredAt: Date.now(),
  };
}
