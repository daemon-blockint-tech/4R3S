import { describe, it, expect } from 'vitest';
import {
  AI_REDTEAM_PLAYBOOK,
  AI_REDTEAM_TECHNIQUE_IDS,
  aiRedTeamBriefing,
  redTeamTechnique,
} from '../resources/ai-redteam-playbook.js';

describe('AI red-team playbook (distilled from L1B3RT4S / P4RS3LT0NGV3)', () => {
  it('has the full distilled technique set', () => {
    expect(AI_REDTEAM_PLAYBOOK.length).toBeGreaterThanOrEqual(15);
    expect(AI_REDTEAM_TECHNIQUE_IDS.length).toBe(AI_REDTEAM_PLAYBOOK.length);
  });

  it('every technique is well-formed (all fields, kebab-case id)', () => {
    for (const t of AI_REDTEAM_PLAYBOOK) {
      expect(t.id).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
      for (const field of ['category', 'principle', 'redteamUse', 'defense'] as const) {
        expect(typeof t[field]).toBe('string');
        expect(t[field].length).toBeGreaterThan(10);
      }
    }
  });

  it('ids are unique', () => {
    expect(new Set(AI_REDTEAM_TECHNIQUE_IDS).size).toBe(AI_REDTEAM_TECHNIQUE_IDS.length);
  });

  it('covers the load-bearing technique classes', () => {
    for (const id of ['refusal-suppression-inversion', 'prefill-affirmation', 'format-scaffold-hijack', 'stacked-composition']) {
      expect(AI_REDTEAM_TECHNIQUE_IDS).toContain(id);
    }
  });

  it('lookup resolves a known id and rejects unknown', () => {
    expect(redTeamTechnique('format-scaffold-hijack')?.category).toMatch(/format/i);
    expect(redTeamTechnique('does-not-exist')).toBeUndefined();
  });

  it('briefing is a non-empty multi-line summary', () => {
    const brief = aiRedTeamBriefing();
    expect(brief.length).toBeGreaterThan(100);
    expect(brief.split('\n').length).toBe(AI_REDTEAM_PLAYBOOK.length);
  });

  it('every technique carries a defensive countermeasure (this is defensive methodology)', () => {
    expect(AI_REDTEAM_PLAYBOOK.every(t => t.defense.trim().length > 0)).toBe(true);
  });
});
