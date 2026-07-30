/**
 * ANALYZE (on-chain) node — load the target program from chain and reason about
 * its security posture from the tool evidence. Part of the parallel ANALYZE
 * superstep. Contributes findings with source "onchain".
 *
 * Reports its outcome on the `analyzers` channel so REPORT can tell a clean
 * on-chain review apart from one that never happened: an RPC error and a
 * genuinely absent program both end with zero findings here, and only one of
 * those means the report carries real on-chain assurance.
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { loadProgram, type ProgramInfo } from "../../tools/solana.js";
import { isKnownProgram, getKnownProgram } from "../../knowledge/known-programs.js";
import type { GraphDeps } from "../deps.js";
import type {
  AnalyzerOutcome,
  AnalyzerReport,
  AresState,
  AresStateUpdate,
  Finding,
} from "../state.js";
import {
  chatJsonResult,
  coerceFindings,
  extractChecked,
  downgradeSpeculative,
} from "../util.js";

/** Build this node's entry for the `analyzers` channel. */
function status(outcome: AnalyzerOutcome, detail?: string): AnalyzerReport[] {
  return [{ analyzer: "onchain", outcome, detail }];
}

/**
 * Findings decided by the decoded account fields alone, before any model sees
 * them. Authority posture is the one class this auditor can settle mechanically:
 * the upgrade authority is a field in the ProgramData account, and who holds it
 * is the difference between "the team can fix a bug" and "one signature replaces
 * the program". `deterministic` marks them so VERIFY may confirm them —
 * re-deriving a decoded byte is not the self-certification that flag guards.
 *
 * A renounced authority produces no finding: it is the safe state, and reporting
 * it as an issue is the noise that made the previous ruleset unusable.
 */
function authorityFindings(program: ProgramInfo): Finding[] {
  if (program.upgradeAuthorityKind === "single-key") {
    return [
      {
        vulnClass: "upgrade authority held by a single key",
        location: program.programDataAddress
          ? `programData:${program.programDataAddress}`
          : program.address,
        severity: "medium",
        evidence:
          `Program ${program.address} is deployed under the BPF upgradeable loader with ` +
          `upgrade authority ${program.upgradeAuthority}, an account owned by the System ` +
          `Program — a plain keypair, not a PDA. One signature from that key replaces the ` +
          `program's executable code, including with logic that drains every account it ` +
          `controls. No timelock or threshold stands in the way.`,
        remediation:
          "Move the upgrade authority to a multisig or on-chain governance with a timelock, " +
          "or renounce upgradeability once the program is stable.",
        source: "onchain",
        category: "upgrade-authority-risk",
        speculative: false,
        confidence: "high",
        deterministic: true,
      },
    ];
  }

  if (program.upgradeAuthorityKind === "program-controlled") {
    return [
      {
        vulnClass: "upgrade authority held by a program-controlled account",
        location: program.programDataAddress
          ? `programData:${program.programDataAddress}`
          : program.address,
        severity: "info",
        evidence:
          `Upgrade authority ${program.upgradeAuthority} is owned by program ` +
          `${program.upgradeAuthorityOwner}, so it is a PDA rather than a keypair. Whether ` +
          `that program enforces a signer threshold or a timelock was not checked here.`,
        remediation:
          "Confirm the controlling program is a multisig or governance program with the " +
          "threshold and timelock the protocol claims, and that its own authority is not " +
          "a single key.",
        source: "onchain",
        category: "upgrade-authority-risk",
        speculative: false,
        confidence: "high",
        deterministic: true,
      },
    ];
  }

  return [];
}

export function makeAnalyzeOnchainNode(deps: GraphDeps) {
  return async function analyzeOnchain(
    state: AresState,
  ): Promise<AresStateUpdate> {
    if (!state.programAddress) {
      return {
        findings: [],
        analyzers: status("skipped", "no program address supplied"),
      };
    }

    const program = await loadProgram(state.programAddress);

    // An RPC error (or an unparseable address) is not a clean result — the chain
    // was never actually read, so silence here means nothing.
    if (program.error) {
      logger.warn(
        {
          component: "node.analyze-onchain",
          address: state.programAddress,
          err: program.error,
        },
        "On-chain analysis could not read the program",
      );
      return {
        findings: [],
        iterations: 0,
        analyzers: status("failed", `could not read program: ${program.error}`),
      };
    }

    if (!program.exists) {
      logger.info(
        { component: "node.analyze-onchain", address: state.programAddress },
        "Program not found on chain; no on-chain findings",
      );
      return {
        findings: [],
        iterations: 0,
        analyzers: status(
          "degraded",
          "program account not found on chain — nothing to analyze",
        ),
      };
    }

    // Decided before the model is called, so an unparseable response cannot cost
    // us the one class this analyzer can settle without it.
    const deterministic = authorityFindings(program);

    const human = [
      "On-chain program metadata (tool output):",
      JSON.stringify(program, null, 2),
      "",
      state.intake ? `Intake: ${state.intake.summary}` : "",
      "",
      "Based ONLY on this evidence, return a JSON object: { findings: [...], checked: [...] }.",
      "Each finding: { category, vulnClass, location, severity, evidence, remediation }.",
      "List every checklist class you evaluated in checked, even if no issue was found.",
      "If the evidence shows no security-relevant signal, return { findings: [], checked: [...] }.",
    ]
      .filter(Boolean)
      .join("\n");

    const { value: raw, parsed } = await chatJsonResult<unknown>(
      deps.chat,
      analyzeSystemPrompt(),
      human,
      [],
    );
    let findings: Finding[] = coerceFindings(raw, "onchain");
    const coverage = extractChecked(raw);

    // Downgrade on-chain findings for known canonical programs.
    if (state.programAddress && isKnownProgram(state.programAddress)) {
      findings = downgradeSpeculative(findings);
      logger.info(
        { component: "node.analyze-onchain", reason: `known program (${getKnownProgram(state.programAddress)?.name})`, downgraded: findings.length },
        "Findings downgraded to speculative",
      );
    }

    // Appended after the downgrade on purpose. That rule exists because
    // pattern-matching a battle-tested program yields noise; a decoded account
    // field is not pattern-matching, and a canonical program's authority posture
    // is exactly as true — and as worth stating — as any other program's.
    findings = [...deterministic, ...findings];
    if (deterministic.length > 0 && !coverage.includes("upgrade-authority-risk")) {
      coverage.push("upgrade-authority-risk");
    }

    logger.info(
      { component: "node.analyze-onchain", findings: findings.length, coverage: coverage.length, speculative: findings.filter((f) => f.speculative).length },
      "On-chain analysis complete",
    );
    return {
      findings,
      coverage,
      iterations: 1,
      analyzers: parsed
        ? status("ok")
        : status(
            "degraded",
            "model response was not valid JSON; no findings extracted",
          ),
    };
  };
}
