/**
 * ANALYZE (heuristic) node — pure LLM reasoning over the intake summary and
 * recalled memory, independent of the on-chain/static tool outputs (which are
 * produced by sibling nodes in the same superstep). Contributes findings with
 * source "heuristic".
 *
 * Reports its outcome on the `analyzers` channel: this node's only failure mode
 * is a response that doesn't parse, which yields zero findings and would
 * otherwise be indistinguishable from "nothing to flag".
 */
import { analyzeSystemPrompt } from "../../llm/prompts.js";
import { logger } from "../../config/logger.js";
import { isKnownProgram, getKnownProgram } from "../../knowledge/known-programs.js";
import { formatSourceForPrompt, citesLoadedFile } from "../../tools/source.js";
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
  fenceUntrusted,
} from "../util.js";

/** Build this node's entry for the `analyzers` channel. */
function status(outcome: AnalyzerOutcome, detail?: string): AnalyzerReport[] {
  return [{ analyzer: "heuristic", outcome, detail }];
}

export function makeAnalyzeHeuristicNode(deps: GraphDeps) {
  return async function analyzeHeuristic(
    state: AresState,
  ): Promise<AresStateUpdate> {
    const memory = state.recalled
      .slice(0, 8)
      .map((s, i) => `#${i + 1} (${s.crystal.level}): ${s.crystal.content}`)
      .join("\n");

    const source = state.source;
    const hasSource = Boolean(source?.available && source.files.length > 0);
    const sourceBlock = hasSource ? formatSourceForPrompt(source!) : "";

    const human = [
      state.intake
        ? `Intake summary: ${state.intake.summary}`
        : `Request: ${state.request}`,
      state.intake?.concerns?.length
        ? `Concerns: ${state.intake.concerns.join(", ")}`
        : "",
      "",
      // Not "prior audit knowledge". That phrasing asserts current truth about
      // text that carries no revision key and no freshness: a fragment was
      // written against the code as it stood in an EARLIER audit, and nothing
      // re-observes the repository between runs to invalidate it. Stating the
      // liveness truth is the cheap half of the fix — the age/level plumbing is
      // a separate change, and printing a date before `created_at` is real would
      // be worse than printing none.
      //
      // The second sentence is the load-bearing one: it forbids the escalation
      // where recalled prose becomes a finding's evidence. `canBeConfirmed` can
      // then only be reached through source the analyzer actually read.
      "Recalled memory from EARLIER audits of this or similar targets. The code",
      "may have changed since. Treat each as a LEAD to re-check against the source",
      "below — a finding may never cite memory as its evidence.",
      memory ? fenceUntrusted(memory, 4_000) : "(none)",
      "",
      hasSource
        ? [
            "PROGRAM SOURCE. Line numbers are shown to the left of each line; cite them.",
            source!.truncated
              ? `NOTE: only ${source!.files.length} of ${source!.discovered.length} discovered files fit the context budget. Classes you could not examine belong in "checked" only if you actually evaluated them.`
              : "",
            "",
            // The audited program's own text is the most attacker-reachable
            // content in this prompt: an ad-hoc marker (or a fake BEGIN/END
            // inside the payload) would let it close the block and address the
            // model as the operator. fenceUntrusted strips such markers.
            // loadSource already bounded the size, so the fence budget is the
            // formatted length itself — a second truncation would only cut
            // real source.
            fenceUntrusted(sourceBlock, sourceBlock.length),
            "",
            "Analyze the source above. Every finding MUST cite a real location as",
            '"<file>:<line>" using a path shown in the source and a line you actually',
            "read there. Quote the offending line verbatim in evidence. If you cannot",
            "point at a specific line, do not report the finding.",
          ]
            .filter(Boolean)
            .join("\n")
        : [
            "NO SOURCE CODE IS AVAILABLE for this target — you are auditing black-box.",
            "You have not seen this program's code. Do not invent file paths, line",
            "numbers, or code excerpts. Report only what the metadata and prior",
            "knowledge above genuinely support, as info/low severity, and say in",
            "evidence that it is a pattern-based hypothesis rather than an observation.",
          ].join("\n"),
      "",
      "Return a JSON object: { findings: [...], checked: [...] }. Each finding:",
      "{ category, vulnClass, location, severity, evidence, remediation }. List every",
      "checklist class you evaluated in checked. Return { findings: [], checked: [...] }",
      "if you have no basis to report anything.",
    ]
      .filter(Boolean)
      .join("\n");

    const { value: raw, parsed } = await chatJsonResult<unknown>(
      deps.chat,
      analyzeSystemPrompt(),
      human,
      [],
    );
    let findings: Finding[] = coerceFindings(raw, "heuristic");
    const coverage = extractChecked(raw);

    // Downgrade heuristic findings to speculative when:
    //   1. No source was actually READ (black-box audit) — note this keys off the
    //      loaded source, not off `sourcePath` being set: a path that was supplied
    //      but could not be read leaves the model just as blind, and the old check
    //      let those findings through at full severity.
    //   2. Target is a known canonical program (noise from pattern-matching).
    const target = state.programAddress ?? state.intake?.target ?? "";
    const known = target ? isKnownProgram(target) : false;
    if (known || !hasSource) {
      const reason = known
        ? `known program (${getKnownProgram(target)?.name})`
        : "no source code read (black-box)";
      findings = downgradeSpeculative(findings);
      logger.info(
        { component: "node.analyze-heuristic", reason, downgraded: findings.length },
        "Findings downgraded to speculative",
      );
    } else {
      // Source was in context, so a citation is checkable. A finding pointing at
      // a file this run never read was not observed — it was composed — and that
      // is the dominant false-positive mode this analyzer had. Demote rather than
      // drop: a real issue described with a wrong path is still worth a look, but
      // it must not carry the authority of a grounded finding.
      const uncited = findings.filter((f) => !citesLoadedFile(f.location, source!));
      if (uncited.length > 0) {
        const uncitedSet = new Set(uncited);
        findings = findings.map((f) =>
          uncitedSet.has(f) ? downgradeSpeculative([f])[0]! : f,
        );
        logger.warn(
          {
            component: "node.analyze-heuristic",
            uncited: uncited.length,
            total: findings.length,
            locations: uncited.map((f) => f.location).slice(0, 5),
          },
          "Findings cited files that were never loaded; downgraded to speculative",
        );
      }
    }

    logger.info(
      { component: "node.analyze-heuristic", findings: findings.length, coverage: coverage.length, speculative: findings.filter((f) => f.speculative).length },
      "Heuristic analysis complete",
    );
    return {
      findings,
      coverage,
      iterations: 1,
      analyzers: parsed
        ? status(
            "ok",
            !hasSource
              ? "black-box: no source read, findings downgraded to speculative"
              : source!.truncated
                ? `source truncated: read ${source!.files.length} of ${source!.discovered.length} files`
                : undefined,
          )
        : status(
            "degraded",
            "model response was not valid JSON; no findings extracted",
          ),
    };
  };
}
