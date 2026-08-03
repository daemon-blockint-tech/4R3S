/**
 * ARES Pack Hunt — shared-workspace types (Phase-2)
 *
 * The Pack Hunt is N specialized agents exploring ONE target in parallel, sharing a
 * live workspace (this board), posting leads, and claiming work so they don't re-tread.
 * See the pack-hunt design ("Shared workspace / lead-board" +
 * "Lead & work coordination").
 *
 * This file is the DATA layer only — pure types, no behavior. The `PackBoard` in
 * `./board.js` is an append-only event log that folds these into projections.
 *
 * Design constraints these types encode (all load-bearing per the red-team, §2):
 *  - A `Lead` is a lightweight *card*, NOT a vault Finding. It carries a foreign key
 *    (`where.targetId`) back to the provenance-gated `Finding.id` when one exists; the
 *    board never launders provenance itself (HT-1). `provenance` here is a plain flag.
 *  - `version` + `claim` exist so `claim()` can be a REAL synchronous compare-and-set
 *    (HT-1: "the claim-lock is advisory" → make it atomic).
 *  - `refutations` is append-only and NEVER unilaterally flips `status` (HT-2: a false
 *    refute must not permanently block re-finding a real bug).
 */

import type { Severity } from '../types/index.js';

// =============================================================================
// LEAD — the unit of shared work on the board
// =============================================================================

/** Where a lead points. Mirrors cli-swarm's `{file, line}` coordinates and adds the
 *  optional foreign keys the design calls for (a URL surface, or the vault `Finding.id`
 *  this card mirrors). Every field is optional — a recon lead may have only a `url`. */
export interface LeadWhere {
  /** Repo-relative source path (cli-swarm's `file`). */
  file?: string;
  /** 1-indexed line (cli-swarm's `line`; bucketed into the dedupKey). */
  line?: number;
  /** A networked surface (endpoint / host) when the lead isn't source-anchored. */
  url?: string;
  /** Foreign key back to the vault's provenance-gated `Finding.id`, once one exists.
   *  The board mirrors finding *cards*; it does not own or gate the finding itself. */
  targetId?: string;
}

/** Lifecycle of a lead. Mirrors cli-swarm's `open → claimed → confirmed/refuted` and
 *  adds `dead` for leases/leads the reaper or a quorum retires.
 *
 *  IMPORTANT: `refuted` is only reachable through the audit quorum (Phase-3), never by a
 *  single `refute()` call — see PackBoard.refute (HT-2). `refute()` only appends a vote. */
export type LeadStatus = 'open' | 'claimed' | 'confirmed' | 'refuted' | 'dead';

/** How the lead's backing evidence was produced — the same three-way flag the honesty
 *  gate keys on (`Finding.verifyGate.provenance`: 'none' | 'context' | 'tool'). A card is
 *  *not trusted* until a real reproduction upgrades it; this is a plain label, not a gate. */
export type LeadProvenance = 'tool' | 'context' | 'none';

/** A lease-based soft lock on a lead. Held by exactly one agent at a time; reaped by
 *  `releaseExpiredClaims(now)` when `leaseUntil` passes (the same timeout-backstop idea
 *  that reaps wedged dispatches). `version` is the CAS token claim() compared against. */
export interface LeadClaim {
  /** Agent id currently holding the lease. */
  by: string;
  /** Epoch-ms after which the lease is stale and reclaimable. */
  leaseUntil: number;
  /** The lead `version` at the moment the claim was granted (for observability/debugging). */
  version: number;
}

/** An endorsement or refutation vote. Append-only; never mutates or deletes prior votes. */
export interface LeadVote {
  /** Agent id casting the vote. */
  by: string;
  /** Free-text rationale (an endorsement note, or a claimed "killing guard" for a refute). */
  note?: string;
  /** For a refutation: the cited guard `file:line`. The quorum (Phase-3) MUST verify this
   *  with `guardExistsInSource()`; a cited-but-absent guard downgrades the vote (HT-2). */
  guard?: string;
  /** When the vote was cast (epoch ms). */
  at: number;
}

/**
 * A lead card on the shared board. A `kind:'work'` lead is a claimed sub-surface / task
 * ("I own the auth module"); a `kind:'lead'` is a suspected vuln. Both live in the same
 * map so claim/endorse/refute work uniformly.
 */
export interface Lead {
  /** Stable board id (randomUUID). NOT the vault Finding.id — see `where.targetId`. */
  id: string;
  /** Collision key for de-dup: file::cwe::line-bucket (cli-swarm's `dedupKey`). Two posts
   *  with the same key are the SAME lead — the second collapses into an endorsement. */
  dedupKey: string;
  /** A suspected vulnerability (`lead`) vs a claimed piece of work / sub-surface (`work`). */
  kind: 'lead' | 'work';
  /** One-line human title. */
  title: string;
  /** Where the lead points (source coords / url / vault FK). */
  where: LeadWhere;
  /** Specialist vuln-class key — cli-swarm's LENSES vocabulary (e.g. 'injection',
   *  'path-traversal', 'ssrf-redirect'), or a free key for work items. */
  vulnClass: string;
  /** Poster's self-reported confidence. Advisory only; never promotes a card by itself. */
  confidence: 'high' | 'medium' | 'low';
  /** Lifecycle state. Only the quorum flips to confirmed/refuted; the board never does. */
  status: LeadStatus;
  /** "Chase-the-smoke" priority: rises each time a duplicate collapses into an endorsement,
   *  and with each independent endorsement. The situation report ranks unclaimed leads by it. */
  smoke: number;
  /** Agent id that first posted the lead. */
  postedBy: string;
  /** Append-only endorsement votes (duplicates fold in here, raising `smoke`). */
  endorsements: LeadVote[];
  /** Append-only refutation votes. Does NOT flip status on its own (HT-2). */
  refutations: LeadVote[];
  /** Present iff currently claimed (a live, unexpired lease). */
  claim?: LeadClaim;
  /** Provenance flag of the backing evidence. A card is untrusted until reproduced. */
  provenance: LeadProvenance;
  /** Monotonic optimistic-concurrency counter. Bumped on every state change; the CAS token. */
  version: number;
  /** When the card first appeared (epoch ms). */
  postedAt: number;
  /** Last time any projection-visible field changed (epoch ms). */
  updatedAt: number;
  /** Optional severity hint carried from the poster (advisory; the vault owns the real one). */
  severity?: Severity;
}

// =============================================================================
// BOARD EVENTS — the append-only log's record type
// =============================================================================

/** One entry in the board's append-only event log. Every mutation emits exactly one of
 *  these (also re-emitted on the EventEmitter as `board:event`), so the full history is
 *  replayable and the projections are a pure fold over `type`. */
export interface BoardEvent {
  /** Unique event id (randomUUID). */
  id: string;
  /** What happened. */
  type:
    | 'lead:posted'
    | 'lead:endorsed'
    | 'lead:refuted'
    | 'lead:claimed'
    | 'lead:claim-denied'
    | 'lead:claim-released'
    | 'lead:status-changed'
    | 'agent:heartbeat';
  /** Agent id that caused the event (the actor). */
  actor: string;
  /** The lead this event is about, when applicable. */
  leadId?: string;
  /** Small, structured extra data (dedupKey collapsed-into, old→new status, etc.). */
  data?: Record<string, unknown>;
  /** Epoch-ms sequence timestamp (the log is ordered by append, this is for display). */
  at: number;
}

// =============================================================================
// AGENT STATUS — per-agent heartbeat projection
// =============================================================================

/** What an agent is doing right now. Used to know which agents are live (for the situation
 *  report's "live agents" line and, in Phase-3, for electing an idle audit panel). */
export type AgentActivity = 'idle' | 'hunting' | 'auditing' | 'reporting' | 'gone';

/** A per-agent heartbeat, folded from the latest `agent:heartbeat` event for that agent. */
export interface AgentStatus {
  /** Agent id. */
  agentId: string;
  /** Current activity. `gone` marks an agent past its liveness window. */
  activity: AgentActivity;
  /** Optional one-line note ("owning auth module", "refuting lead X"). */
  note?: string;
  /** Epoch-ms of the last heartbeat — liveness is derived from this + a staleness window. */
  lastSeen: number;
}
