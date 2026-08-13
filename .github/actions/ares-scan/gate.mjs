#!/usr/bin/env node
// INT-5's severity gate. Deliberately a small, standalone script rather than
// inline shell — this repo's own SEVERITY_RANK (src/knowledge/finding.ts)
// isn't something this Action can cleanly import (it runs against whatever
// ref of the auditor repo was checked out, from outside that repo's own
// build), so this mirrors that same ordering explicitly. If that file's
// ranking ever changes, this needs updating too — that's the tradeoff of a
// mirror over a real import, made deliberately rather than by accident.
import { readFile, appendFile } from "node:fs/promises";

const SEVERITY_RANK = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const [, , findingsPath, thresholdArg, warnThresholdArg] = process.argv;

function fail(message) {
  console.error(`::error::${message}`);
  process.exitCode = 1;
}

function warn(message) {
  console.log(`::warning::${message}`);
}

async function setOutput(name, value) {
  const githubOutput = process.env.GITHUB_OUTPUT;
  if (!githubOutput) return; // not running in a real Actions runner
  await appendFile(githubOutput, `${name}=${value}\n`, "utf8");
}

async function main() {
  const threshold = (thresholdArg ?? "critical").toLowerCase();
  if (!(threshold in SEVERITY_RANK)) {
    fail(
      `Unknown severity-threshold "${threshold}" — expected one of: ${Object.keys(SEVERITY_RANK).join(", ")}`,
    );
    return;
  }

  const warnThresholdRaw = (warnThresholdArg ?? "none").toLowerCase();
  const warnDisabled = warnThresholdRaw === "none" || warnThresholdRaw === "";
  if (!warnDisabled && !(warnThresholdRaw in SEVERITY_RANK)) {
    fail(
      `Unknown warn-severity-threshold "${warnThresholdRaw}" — expected "none" or one of: ${Object.keys(SEVERITY_RANK).join(", ")}`,
    );
    return;
  }

  let raw;
  try {
    raw = await readFile(findingsPath, "utf8");
  } catch (err) {
    // A scan that genuinely found nothing still writes `[]` — a missing
    // file specifically means the audit itself never completed (crashed,
    // or --report-json was silently dropped somewhere upstream). Treat
    // that as a gate failure, not a silent pass — the exact failure shape
    // ORC2-F6 already found once for a different tool in this repo.
    fail(`Could not read findings file at ${findingsPath}: ${err.message}`);
    return;
  }

  let findings;
  try {
    findings = JSON.parse(raw);
  } catch (err) {
    fail(`Findings file at ${findingsPath} was not valid JSON: ${err.message}`);
    return;
  }

  await setOutput("findings-json", findingsPath);
  await setOutput("finding-count", String(findings.length));

  // Excludes findings VERIFY already marked as false-positive — gating a
  // CI check on findings the pipeline's own verification step has already
  // ruled out would make every false-positive a build failure with no way
  // to unblock it short of raising the threshold for everyone.
  const relevant = findings.filter((f) => f.status !== "false-positive");
  const blocking = relevant.filter(
    (f) => (SEVERITY_RANK[f.severity] ?? 0) >= SEVERITY_RANK[threshold],
  );
  // Strictly below the fail threshold — those already get a hard error, not
  // also a separate warning for the same finding.
  const warning = warnDisabled
    ? []
    : relevant.filter(
        (f) =>
          (SEVERITY_RANK[f.severity] ?? 0) >= SEVERITY_RANK[warnThresholdRaw] &&
          (SEVERITY_RANK[f.severity] ?? 0) < SEVERITY_RANK[threshold],
      );

  const bySeverity = {};
  for (const f of relevant) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  }
  console.log(`ARES scan: ${findings.length} finding(s) total, ${relevant.length} after excluding confirmed false-positives.`);
  console.log(`By severity: ${JSON.stringify(bySeverity)}`);
  console.log(`Threshold: ${threshold} and above fails the check.${warnDisabled ? "" : ` ${warnThresholdRaw} and above (below ${threshold}) warns without failing.`}`);

  if (warning.length > 0) {
    console.log(`\n${warning.length} finding(s) at or above "${warnThresholdRaw}" but below the fail threshold:\n`);
    for (const f of warning) {
      const message = `[${f.severity}] ${f.vulnClass} — ${f.location}`;
      console.log(`  ${message}`);
      warn(message);
    }
  }

  if (blocking.length > 0) {
    console.log(`\n${blocking.length} finding(s) at or above "${threshold}":\n`);
    for (const f of blocking) {
      console.log(`  [${f.severity}] ${f.vulnClass} — ${f.location}`);
    }
    await setOutput("gate-passed", "false");
    fail(
      `${blocking.length} finding(s) at or above severity "${threshold}" — failing the check.`,
    );
  } else {
    await setOutput("gate-passed", "true");
    console.log("\nNo findings at or above the fail threshold.");
  }
}

main().catch((err) => {
  fail(`Gate script crashed: ${err.stack ?? err}`);
});
