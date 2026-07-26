/**
 * Audit thread identity.
 *
 * The checkpointer keys graph state by `thread_id`, and LangGraph resumes an
 * interrupted run when one is pending on that thread — even if the new
 * invocation carries a different target. A single shared thread id therefore
 * lets a crashed audit of program X be resumed by a later audit of program Y,
 * splicing the new target into the old run's state.
 *
 * So the default thread id is derived from the target instead: two audits of
 * the same program share a thread (and stay resumable), while audits of
 * different targets can never collide. Setting `ARES_THREAD_ID` overrides this
 * and pins every run to one thread, which is what you want for deliberately
 * continuing a specific audit.
 */
import { createHash } from "node:crypto";
import { resolve } from "node:path";

export interface AuditTarget {
  /** On-chain program address, when auditing a deployed program. */
  program?: string;
  /** Local source path, when auditing source. */
  source?: string;
  /** Explicit `ARES_THREAD_ID`; wins over the derived id when set. */
  override?: string;
}

/**
 * Stable thread id for an audit target. The source path is resolved to an
 * absolute path first, so `./prog` and `prog` are the same audit.
 */
export function auditThreadId(target: AuditTarget): string {
  const override = target.override?.trim();
  if (override) return override;

  const key = [
    target.program?.trim() ?? "",
    target.source ? resolve(target.source) : "",
  ].join("|");
  return `ares-${createHash("sha256").update(key).digest("hex").slice(0, 16)}`;
}
