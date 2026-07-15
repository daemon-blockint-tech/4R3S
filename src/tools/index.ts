/**
 * Audit tools barrel.
 *
 * Current tools:
 *   - solana:  on-chain program introspection (Helius / RPC).
 *   - semgrep: static analysis over source code.
 *
 * Extension point: additional tools can be exposed to the agent via the Model
 * Context Protocol (MCP). An MCP client would live alongside these modules and
 * surface remote tools with the same "load / run / normalize" shape, so the
 * analyzer nodes stay agnostic to where a tool actually executes.
 */
export { loadProgram, type ProgramInfo } from "./solana.js";
export {
  runSemgrep,
  type SemgrepResult,
  type SemgrepFinding,
} from "./semgrep.js";
