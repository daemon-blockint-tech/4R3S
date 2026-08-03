import { describe, expect, it } from 'vitest';
import { syncLocalAgentSelection } from '../agent/local-agents.js';

describe('syncLocalAgentSelection', () => {
  it('disconnects agents omitted from the bulk selection', () => {
    const connected = new Map([
      ['codex', { id: 'codex' }],
      ['hermes', { id: 'hermes' }],
    ]);

    syncLocalAgentSelection(connected, ['hermes'], true);

    expect([...connected.keys()]).toEqual(['hermes']);
  });

  it('preserves existing agents for an additive single-agent connect', () => {
    const connected = new Map([
      ['codex', { id: 'codex' }],
      ['hermes', { id: 'hermes' }],
    ]);

    syncLocalAgentSelection(connected, ['hermes'], false);

    expect([...connected.keys()]).toEqual(['codex', 'hermes']);
  });

  it('disconnects every agent when the bulk selection is empty', () => {
    const connected = new Map([
      ['codex', { id: 'codex' }],
      ['hermes', { id: 'hermes' }],
    ]);

    syncLocalAgentSelection(connected, [], true);

    expect(connected.size).toBe(0);
  });
});
