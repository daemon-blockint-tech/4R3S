use ares_core::{AresError, AresResult};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, error, info};

/// Trident integration layer for ARES V3.
/// Wraps `trident-cli` as an MCP-style tool that the agent orchestrator can call.
pub struct TridentTool {
    trident_path: PathBuf,
    working_dir: PathBuf,
}

impl TridentTool {
    /// Discover `trident-cli` on the system PATH or use configured path.
    pub fn new(configured_path: Option<&Path>) -> AresResult<Self> {
        let trident_path = if let Some(p) = configured_path {
            p.to_path_buf()
        } else {
            which::which("trident").map_err(|_| {
                AresError::ToolMissing(
                    "trident-cli not found on PATH. Install via: cargo install trident-cli"
                        .to_string(),
                )
            })?
        };

        if !trident_path.exists() {
            return Err(AresError::ToolMissing(format!(
                "Configured trident path does not exist: {:?}",
                trident_path
            )));
        }

        info!("Trident tool initialized: {:?}", trident_path);
        Ok(Self {
            trident_path,
            working_dir: PathBuf::from("."),
        })
    }

    /// Set working directory for subsequent commands.
    pub fn with_working_dir(mut self, dir: PathBuf) -> Self {
        self.working_dir = dir;
        self
    }

    /// Run `trident fuzz run` against a specific fuzz test.
    pub async fn fuzz_run(
        &self,
        fuzz_test_name: &str,
        iterations: u64,
        timeout_secs: u64,
    ) -> AresResult<FuzzRunResult> {
        info!(
            "Running Trident fuzz: test={} iterations={} timeout={}s",
            fuzz_test_name, iterations, timeout_secs
        );

        let mut cmd = Command::new(&self.trident_path);
        cmd.current_dir(&self.working_dir)
            .arg("fuzz")
            .arg("run")
            .arg(fuzz_test_name)
            .arg("--max-iterations")
            .arg(iterations.to_string())
            .env("TRIDENT_MAX_DURATION", timeout_secs.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        debug!("Executing: {:?}", cmd);

        let output = cmd
            .output()
            .await
            .map_err(|e| AresError::Trident(format!("Failed to execute trident fuzz: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() {
            error!(
                "Trident fuzz failed:\nSTDOUT: {}\nSTDERR: {}",
                stdout, stderr
            );
            return Err(AresError::Trident(format!(
                "Fuzz run exited with code {}. stderr: {}",
                output.status,
                stderr.lines().take(20).collect::<Vec<_>>().join("\n")
            )));
        }

        let result = self.parse_fuzz_output(&stdout, &stderr);
        info!(
            "Fuzz completed | iterations_ran={} crashes={} invariant_violations={}",
            result.iterations_ran,
            result.crashes.len(),
            result.invariant_violations.len()
        );

        Ok(result)
    }

    /// Run `trident init` to bootstrap fuzz tests for a new program.
    pub async fn init_fuzz_tests(&self) -> AresResult<()> {
        info!("Initializing Trident fuzz tests in {:?}", self.working_dir);

        let output = Command::new(&self.trident_path)
            .current_dir(&self.working_dir)
            .arg("init")
            .arg("--skip-build")
            .output()
            .await
            .map_err(|e| AresError::Trident(format!("Failed to init fuzz tests: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AresError::Trident(format!("Fuzz init failed: {}", stderr)));
        }

        info!("Trident fuzz tests initialized successfully.");
        Ok(())
    }

    /// Run `trident fuzz run` with a generated harness for a specific vulnerability pattern.
    pub async fn fuzz_with_harness(
        &self,
        harness_name: &str,
        vulnerability_pattern: &str,
        iterations: u64,
    ) -> AresResult<FuzzRunResult> {
        info!(
            "Running targeted fuzz | harness={} pattern={} iterations={}",
            harness_name, vulnerability_pattern, iterations
        );

        // Phase 1 stub: will be enhanced to auto-generate harness based on pattern
        let result = self.fuzz_run(harness_name, iterations, 300).await?;

        Ok(result)
    }

    /// Parse Trident fuzz output into structured results.
    ///
    /// Two things this must get right, both of which it previously got wrong in
    /// the same direction that reaches a client report:
    ///
    /// **It has to read stderr.** A Rust panic — the single most important thing
    /// a fuzzer can find — is printed to stderr as
    /// `thread '<unnamed>' panicked at ...`. The old parser looped over `stdout`
    /// only and took `_stderr` as an ignored argument, so a harness that genuinely
    /// crashed was reported as a clean run whenever its wrapper still exited 0.
    ///
    /// **A count is not an event.** The old parser pushed any line containing
    /// `crash`, `panic` or `ERROR` into `crashes`. Trident's own summary line
    /// `Total crashes: 0` contains "crash", and a startup line like
    /// `[ERROR] no corpus found, starting empty` contains "ERROR" — so a clean run
    /// produced crash entries. `scan.rs` turns each of those into a
    /// `Severity::High` finding at confidence 0.85 whose description is the raw
    /// line, and the economic scorer then attaches extractable value to it. A
    /// scan of a healthy target published "Crash in fuzz target" with the body
    /// "Total crashes: 0".
    ///
    /// So: summary counts are parsed as counts, and only genuine crash evidence
    /// is recorded as a crash.
    fn parse_fuzz_output(&self, stdout: &str, stderr: &str) -> FuzzRunResult {
        let mut crashes = Vec::new();
        let mut invariant_violations = Vec::new();
        let mut iterations_ran = 0u64;
        // `None` when the run never printed a summary at all, which is different
        // from printing zero.
        let mut reported_crashes: Option<u64> = None;

        for line in stdout.lines().chain(stderr.lines()) {
            if let Some(n) = labelled_count(line, "iterations") {
                iterations_ran = n;
            }
            if let Some(n) = labelled_count(line, "crashes") {
                // A tally, not an occurrence. Recorded so `success` can still
                // reflect it, but never pushed as a crash of its own.
                reported_crashes = Some(reported_crashes.unwrap_or(0).max(n));
                continue;
            }
            if is_crash_evidence(line) {
                crashes.push(line.trim().to_string());
            }
            if is_invariant_violation(line) {
                invariant_violations.push(line.trim().to_string());
            }
        }

        let success = crashes.is_empty()
            && invariant_violations.is_empty()
            && reported_crashes.unwrap_or(0) == 0;

        FuzzRunResult {
            iterations_ran,
            success,
            crashes,
            invariant_violations,
            coverage_percent: None,
            raw_stdout: stdout.to_string(),
            raw_stderr: stderr.to_string(),
        }
    }

    /// Check if a Trident harness file exists for the given target.
    pub fn harness_exists(&self, harness_name: &str) -> bool {
        let harness_path = self
            .working_dir
            .join("trident-tests")
            .join("fuzz_tests")
            .join(format!("test_{}.rs", harness_name));
        harness_path.exists()
    }
}

/// Structured result from a Trident fuzz run.
#[derive(Debug, Clone, Default)]
pub struct FuzzRunResult {
    pub iterations_ran: u64,
    pub success: bool,
    pub crashes: Vec<String>,
    pub invariant_violations: Vec<String>,
    pub coverage_percent: Option<f64>,
    pub raw_stdout: String,
    pub raw_stderr: String,
}

/// Read `label: N` out of a summary line, whatever prefixes it.
///
/// Matches `crashes: 3`, `Total crashes: 0` and `  Iterations: 1200` alike. The
/// label must end on a word boundary so `crashes_recovered: 2` does not read as
/// a crash tally.
fn labelled_count(line: &str, label: &str) -> Option<u64> {
    let lower = line.to_ascii_lowercase();
    let at = lower.find(label)?;
    let after = &lower[at + label.len()..];
    let rest = after.trim_start();
    let rest = rest.strip_prefix(':')?;
    rest.split_whitespace()
        .next()?
        .trim_end_matches(|c: char| !c.is_ascii_digit())
        .parse()
        .ok()
}

/// True when the line is evidence that something actually crashed.
///
/// Deliberately narrower than "mentions the word crash". Bare `ERROR` is gone:
/// fuzzers log recoverable errors (missing corpus, unreadable seed) at that level
/// constantly, and treating them as crashes is what filled reports with findings
/// whose body was a log line.
fn is_crash_evidence(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    // The Rust panic itself — on stderr, which is why stderr must be scanned.
    lower.contains("panicked at")
        // Fatal signals a harness can die on. `segv` rather than `sigsegv`:
        // sanitizers report `==12345==ERROR: AddressSanitizer: SEGV`, without the
        // `SIG` prefix, and that line is the crash itself.
        || lower.contains("segv")
        || lower.contains("sigabrt")
        || lower.contains("sanitizer:")
        || lower.contains("signal: 6")
        || lower.contains("signal: 11")
        // Explicit crash reports, as opposed to a tally of them.
        || lower.contains("crash detected")
        || lower.contains("crash found")
        || lower.contains("fuzz target crashed")
        || lower.contains("artifact written to")
}

fn is_invariant_violation(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("invariant violated")
        || lower.contains("assertion failed")
        || lower.contains("check failed")
}

/// Generate a Trident fuzz test template for a given vulnerability category.
pub fn generate_fuzz_harness_template(program_name: &str, vulnerability_pattern: &str) -> String {
    format!(
        r#"use trident::*;
use {}::*;

#[derive(FuzzTestExecutor)]
struct FuzzTarget;

#[init]
fn start(&mut self) {{
    let mut tx = InitializeTransaction::build(&mut self.trident, &mut self.fuzz_accounts);
    self.trident.execute_transaction(&mut tx, Some("Initialize"));
}}

#[flow]
fn exploit_{}(ctx: &mut FuzzContext) {{
    // ARES generated harness for: {}
    // TODO: Implement attack sequence based on vulnerability pattern
    let mut tx = ExploitTransaction::build(&mut ctx.trident, &mut ctx.fuzz_accounts);
    ctx.trident.execute_transaction(&mut tx, Some("Exploit{}"));
}}
"#,
        program_name,
        vulnerability_pattern.to_lowercase().replace(" ", "_"),
        vulnerability_pattern,
        vulnerability_pattern.replace(" ", "")
    )
}

/// Check if Trident is installed and report version.
pub async fn check_trident_installation() -> AresResult<String> {
    match which::which("trident") {
        Ok(path) => {
            let output = Command::new(&path)
                .arg("--version")
                .output()
                .await
                .map_err(|e| AresError::Trident(format!("Failed to check version: {}", e)))?;

            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            info!("Trident found: {} at {:?}", version, path);
            Ok(version)
        }
        Err(_) => Err(AresError::ToolMissing(
            "trident-cli not found. Install: cargo install trident-cli".to_string(),
        )),
    }
}

// ─────────────────────────────────────────────────────────────
// Phase 2: Adaptive fuzzing budget & SVM PoC runner
// ─────────────────────────────────────────────────────────────

/// Budget parameters for adaptive fuzz campaigns.
#[derive(Debug, Clone)]
pub struct FuzzBudget {
    /// Initial batch size to run.
    pub initial_iterations: u64,
    /// Hard ceiling on total iterations.
    pub max_iterations: u64,
    /// Hard ceiling on total wall-clock time (seconds).
    pub max_duration_secs: u64,
    /// Standard batch increment when no crashes are found.
    pub iteration_batch_size: u64,
    /// Bonus multiplier applied to batch size after a crash.
    pub crash_bonus_multiplier: u64,
}

impl Default for FuzzBudget {
    fn default() -> Self {
        Self {
            initial_iterations: 10_000,
            max_iterations: 100_000,
            max_duration_secs: 600,
            iteration_batch_size: 10_000,
            crash_bonus_multiplier: 2,
        }
    }
}

/// Result of running a PoC / test via `cargo test` in SVM.
#[derive(Debug, Clone, Default)]
pub struct TestRunResult {
    pub success: bool,
    pub passed: usize,
    pub failed: usize,
    pub stdout: String,
    pub stderr: String,
}

impl TridentTool {
    /// Adaptive fuzz campaign: starts small, doubles budget on crashes,
    /// respects max iterations / duration / cost proxy.
    pub async fn adaptive_fuzz_run(
        &self,
        target: &str,
        budget: FuzzBudget,
    ) -> AresResult<FuzzRunResult> {
        let mut total_iterations = 0u64;
        let mut all_crashes = Vec::new();
        let mut all_violations = Vec::new();
        let start = std::time::Instant::now();

        let mut current_batch = budget.initial_iterations;

        loop {
            if total_iterations >= budget.max_iterations {
                info!(
                    "Adaptive fuzz: reached max iterations {}",
                    budget.max_iterations
                );
                break;
            }
            let elapsed = start.elapsed().as_secs();
            if elapsed >= budget.max_duration_secs {
                info!(
                    "Adaptive fuzz: reached max duration {}s",
                    budget.max_duration_secs
                );
                break;
            }

            let remaining_iters = budget.max_iterations - total_iterations;
            let batch = current_batch.min(remaining_iters);
            let remaining_secs = budget.max_duration_secs - elapsed;

            info!(
                "Adaptive fuzz batch | target={} batch={} remaining_iters={} remaining_secs={}",
                target, batch, remaining_iters, remaining_secs
            );

            let result = self.fuzz_run(target, batch, remaining_secs).await?;

            let batch_had_crashes = !result.crashes.is_empty();
            let batch_had_violations = !result.invariant_violations.is_empty();

            total_iterations += result.iterations_ran;
            all_crashes.extend(result.crashes);
            all_violations.extend(result.invariant_violations);

            let found_issue = !all_crashes.is_empty() || !all_violations.is_empty();

            if found_issue {
                // Extend budget aggressively when crashes are found
                current_batch = (current_batch * budget.crash_bonus_multiplier)
                    .min(budget.max_iterations - total_iterations)
                    .max(budget.iteration_batch_size);
                info!(
                    "Adaptive fuzz: found crashes/violations — extending next batch to {}",
                    current_batch
                );
            } else {
                // No progress: continue with standard batch
                current_batch = budget
                    .iteration_batch_size
                    .min(budget.max_iterations - total_iterations);
            }

            // Early exit if the last batch completed prematurely (e.g. internal Trident limit)
            if result.iterations_ran < batch && !batch_had_crashes && !batch_had_violations {
                info!("Adaptive fuzz: last batch ended early with no crashes, stopping.");
                break;
            }
        }

        let success = all_crashes.is_empty() && all_violations.is_empty();

        Ok(FuzzRunResult {
            iterations_ran: total_iterations,
            success,
            crashes: all_crashes,
            invariant_violations: all_violations,
            coverage_percent: None,
            raw_stdout: format!(
                "Adaptive fuzz total iterations: {} elapsed: {}s",
                total_iterations,
                start.elapsed().as_secs()
            ),
            raw_stderr: String::new(),
        })
    }

    /// Run a generated PoC file via `cargo test` inside the working directory.
    /// This executes the test in the Solana Program Test (SVM) sandbox.
    pub async fn run_poc_cargo_test(&self, test_filter: &str) -> AresResult<TestRunResult> {
        info!(
            "Running PoC test in SVM sandbox | filter={} dir={:?}",
            test_filter, self.working_dir
        );

        let output = Command::new("cargo")
            .current_dir(&self.working_dir)
            .args(["test", "--", test_filter])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                AresError::Trident(format!("Failed to execute cargo test for PoC: {}", e))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        // Naïve parsing: count "test result: ok" vs failures
        let passed = stdout
            .lines()
            .chain(stderr.lines())
            .filter(|l| l.contains("test result: ok"))
            .count();
        let failed = stdout
            .lines()
            .chain(stderr.lines())
            .filter(|l| l.contains("test result: FAILED") || l.contains("failures:"))
            .count();

        let success = output.status.success();

        if success {
            info!(
                "PoC SVM test completed | passed={} failed={}",
                passed, failed
            );
        } else {
            error!(
                "PoC SVM test failed | passed={} failed={} | stderr snippet: {}",
                passed,
                failed,
                stderr.lines().take(10).collect::<Vec<_>>().join("\n")
            );
        }

        Ok(TestRunResult {
            success,
            passed,
            failed,
            stdout,
            stderr,
        })
    }
}

#[cfg(test)]
mod fuzz_output_parsing_tests {
    use super::*;

    fn parse(stdout: &str, stderr: &str) -> FuzzRunResult {
        TridentTool::new(None)
            .expect("trident tool")
            .parse_fuzz_output(stdout, stderr)
    }

    /// The defect that reached client reports. `scan.rs` turns every entry in
    /// `crashes` into a Severity::High finding at confidence 0.85 whose body is
    /// the raw line, and the economic scorer attaches extractable value to it —
    /// so this summary line published "Crash in fuzz target" with the body
    /// "Total crashes: 0" on a target that never crashed.
    #[test]
    fn a_zero_crash_summary_is_not_a_crash() {
        let r = parse("Iterations: 1000\nTotal crashes: 0\n", "");
        assert!(r.crashes.is_empty(), "got {:?}", r.crashes);
        assert!(
            r.success,
            "a run reporting zero crashes is a successful run"
        );
        assert_eq!(r.iterations_ran, 1000);
    }

    /// Fuzzers log recoverable problems at ERROR constantly. Treating the level
    /// as crash evidence is what filled reports with log lines.
    #[test]
    fn a_recoverable_error_log_line_is_not_a_crash() {
        let r = parse("[ERROR] no corpus found, starting empty\n", "");
        assert!(r.crashes.is_empty(), "got {:?}", r.crashes);
        assert!(r.success);
    }

    /// The other half: a real panic is printed to STDERR, which the parser did
    /// not read at all. A genuinely crashing harness was reported clean.
    #[test]
    fn a_panic_on_stderr_is_detected() {
        let r = parse(
            "Iterations: 42\n",
            "thread '<unnamed>' panicked at fuzz_target.rs:42:9:\nattempt to subtract with overflow\n",
        );
        assert_eq!(r.crashes.len(), 1, "got {:?}", r.crashes);
        assert!(r.crashes[0].contains("panicked at"));
        assert!(!r.success, "a panic must fail the run");
    }

    #[test]
    fn fatal_signals_are_crashes() {
        for line in [
            "process didn't exit successfully: signal: 11",
            "==12345==ERROR: AddressSanitizer: SEGV",
            "harness aborted with SIGABRT",
        ] {
            let r = parse("", line);
            assert!(!r.crashes.is_empty(), "{line:?} should be crash evidence");
            assert!(!r.success);
        }
    }

    /// A non-zero tally still fails the run even when no individual crash line
    /// was matched — the count is believed, it is just not itself a finding.
    #[test]
    fn a_nonzero_crash_count_fails_the_run_without_inventing_a_finding() {
        let r = parse("Total crashes: 3\n", "");
        assert!(
            r.crashes.is_empty(),
            "the tally must not masquerade as a crash entry: {:?}",
            r.crashes
        );
        assert!(!r.success, "3 crashes is not a successful run");
    }

    #[test]
    fn invariant_violations_are_still_detected() {
        let r = parse("CHECK FAILED: total supply decreased\n", "");
        assert_eq!(r.invariant_violations.len(), 1);
        assert!(!r.success);
    }

    #[test]
    fn a_clean_run_is_clean() {
        let r = parse("Iterations: 5000\nTotal crashes: 0\nDone.\n", "");
        assert!(r.success);
        assert!(r.crashes.is_empty() && r.invariant_violations.is_empty());
    }

    // ---- labelled_count boundaries ----

    #[test]
    fn labelled_count_reads_a_tally_whatever_prefixes_it() {
        assert_eq!(labelled_count("Total crashes: 7", "crashes"), Some(7));
        assert_eq!(
            labelled_count("  Iterations:  1200", "iterations"),
            Some(1200)
        );
        assert_eq!(labelled_count("crashes: 0", "crashes"), Some(0));
    }

    #[test]
    fn labelled_count_ignores_a_different_label_that_merely_contains_it() {
        // Would otherwise read as a crash tally of 2.
        assert_eq!(labelled_count("crashes_recovered 2", "crashes"), None);
        assert_eq!(labelled_count("no crashes here", "crashes"), None);
    }
}
