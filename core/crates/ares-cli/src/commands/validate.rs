use ares_core::AresConfig;
use ares_core::AresResult;
use std::path::Path;
use tracing::{error, info, warn};

/// Outcome of running a single PoC file to completion.
///
/// `run_poc` returns `Err` (not a third verdict variant) when the harness
/// could not be run to a trustworthy pass/fail conclusion at all — unknown
/// file extension, or the test/build runner itself failed to spawn. Callers
/// (e.g. POC-2's `confirm` command) should treat that as inconclusive, not as
/// a refutation of the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocVerdict {
    /// The harness ran and the transaction succeeded — the finding reproduces.
    Passed,
    /// The harness ran and the transaction failed — the finding did not reproduce.
    Failed,
    /// The harness did not produce a usable answer, so neither `Passed` nor
    /// `Failed` may be claimed.
    ///
    /// Distinguishing this from `Failed` is not pedantry. `cargo test` exits
    /// non-zero for a compile error exactly as it does for a failing assertion,
    /// so a harness that never built was being reported as evidence the finding
    /// is false — a refutation manufactured out of a syntax error. And it exits
    /// **zero** when a filter matches no test at all, which was being reported as
    /// a confirmed exploit. Both are absence of evidence, not evidence.
    Inconclusive,
}

/// Validate a proof-of-concept in a sandboxed SVM environment.
/// Phase 2: executes real `cargo test` / Trident runs instead of stubs.
/// Phase 8: mainnet fork simulation via `solana-test-validator --clone`.
pub async fn execute(
    poc_path: &Path,
    fork_mainnet: bool,
    fork_slot: Option<u64>,
    config: &AresConfig,
    rpc_url_override: Option<String>,
) -> AresResult<()> {
    info!("ARES PoC Validation");
    info!(
        "PoC: {:?} | Fork Mainnet: {} | Slot: {:?}",
        poc_path, fork_mainnet, fork_slot
    );

    if !poc_path.exists() {
        return Err(ares_core::AresError::NotFound(format!(
            "PoC path not found: {:?}",
            poc_path
        )));
    }

    // Determine project root (nearest directory with Cargo.toml)
    let project_root = match find_project_root(poc_path) {
        Some(root) => root,
        None => {
            error!(
                "Could not locate project root (Cargo.toml) for {:?}",
                poc_path
            );
            return Err(ares_core::AresError::Execution(
                "PoC must reside inside a Rust project with Cargo.toml".to_string(),
            ));
        }
    };
    info!("Resolved project root: {:?}", project_root);

    // Phase 8: Mainnet fork validator orchestration
    let mut validator_handle: Option<crate::fork_validator::ForkValidator> = None;
    let local_rpc: Option<String> = if fork_mainnet || config.mainnet_fork_enabled {
        let rpc_url = rpc_url_override
            .or_else(|| config.mainnet_rpc_url.clone())
            .unwrap_or_else(|| "https://api.mainnet-beta.solana.com".to_string());
        let slot = fork_slot.or(config.mainnet_fork_slot);
        let clone_accounts = config.mainnet_clone_accounts.clone();

        info!(
            "[Phase 8] Starting mainnet fork validator | RPC={} | Slot={:?} | Clones={:?}",
            rpc_url, slot, clone_accounts
        );

        let mut validator = crate::fork_validator::ForkValidator::builder(rpc_url)
            .slot(slot)
            .clone_accounts(clone_accounts)
            .build();

        match validator.start().await {
            Ok(url) => {
                info!("Mainnet fork validator ready at {}", url);
                validator_handle = Some(validator);
                Some(url)
            }
            Err(e) => {
                error!(
                    "Failed to start fork validator: {}. Continuing without fork.",
                    e
                );
                None
            }
        }
    } else {
        None
    };

    let result = run_poc(poc_path, &project_root, local_rpc.as_deref()).await;

    // Phase 8: Stop validator if it was started
    if let Some(validator) = validator_handle {
        validator.stop().await;
        info!("Fork validator stopped.");
    }

    result.map(|_verdict| ())
}

/// Run a single PoC file (`.rs`, `.ts`, or `.sh`) to completion and report
/// whether it passed or failed. `local_rpc`, when set, is injected as
/// `ARES_FORK_RPC_URL` (Rust/shell) or `ANCHOR_PROVIDER_URL` (TypeScript) so
/// the harness targets a mainnet-forked validator instead of an ephemeral one.
pub async fn run_poc(
    poc_path: &Path,
    project_root: &Path,
    local_rpc: Option<&str>,
) -> AresResult<PocVerdict> {
    let extension = poc_path.extension().and_then(|e| e.to_str());

    match extension {
        Some("rs") => {
            info!("Detected Rust test file. Building and running via cargo test in SVM...");

            let test_filter = poc_test_filter(poc_path);

            let mut cmd = tokio::process::Command::new("cargo");
            cmd.current_dir(project_root)
                .args(["test", test_filter, "--", "--nocapture"]);
            if let Some(rpc) = local_rpc {
                cmd.env("ARES_FORK_RPC_URL", rpc);
            }
            let output = cmd.output().await;

            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    info!("{}", stdout.lines().take(30).collect::<Vec<_>>().join("\n"));
                    if !stderr.is_empty() {
                        info!(
                            "stderr: {}",
                            stderr.lines().take(10).collect::<Vec<_>>().join("\n")
                        );
                    }
                    // A verdict may only be read off the exit code once we know a
                    // test actually executed.
                    let combined = format!("{stdout}{stderr}");
                    match tests_executed(&combined) {
                        None => {
                            // libtest prints a `test result:` summary iff a test
                            // binary ran; a compile error never reaches it.
                            warn!(
                                "PoC INCONCLUSIVE — the harness never ran (build or link failure). \
                                 Not treating this as a refutation."
                            );
                            Ok(PocVerdict::Inconclusive)
                        }
                        Some(0) => {
                            // `cargo test <filter>` exits 0 when the filter matches
                            // nothing, so this would otherwise read as a confirmed
                            // exploit produced by running no code at all.
                            warn!(
                                "PoC INCONCLUSIVE — filter {test_filter:?} matched no test. \
                                 Not treating an empty run as a confirmation."
                            );
                            Ok(PocVerdict::Inconclusive)
                        }
                        Some(_) if o.status.success() => {
                            info!("PoC validation PASSED — the attack transaction was accepted.");
                            Ok(PocVerdict::Passed)
                        }
                        Some(_) => {
                            info!("PoC validation FAILED — the program rejected the attack.");
                            Ok(PocVerdict::Failed)
                        }
                    }
                }
                Err(e) => Err(ares_core::AresError::Execution(format!(
                    "cargo test failed: {}",
                    e
                ))),
            }
        }
        Some("ts") => {
            info!("Detected TypeScript test file. Running via anchor test...");
            let mut cmd = tokio::process::Command::new("anchor");
            cmd.current_dir(project_root).args(["test", "--skip-build"]);
            if let Some(rpc) = local_rpc {
                cmd.env("ANCHOR_PROVIDER_URL", rpc);
            }
            let output = cmd.output().await;
            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    if o.status.success() {
                        info!("Anchor test completed successfully.");
                        info!("{}", stdout.lines().take(20).collect::<Vec<_>>().join("\n"));
                        Ok(PocVerdict::Passed)
                    } else {
                        error!("Anchor test failed.");
                        error!("{}", String::from_utf8_lossy(&o.stderr));
                        Ok(PocVerdict::Failed)
                    }
                }
                Err(e) => {
                    error!("Failed to run anchor test: {}", e);
                    Err(ares_core::AresError::Execution(format!(
                        "anchor test failed: {}",
                        e
                    )))
                }
            }
        }
        Some("sh") => {
            info!("Detected shell script. Executing in local environment...");
            let mut cmd = tokio::process::Command::new("bash");
            cmd.current_dir(project_root).arg(poc_path);
            if let Some(rpc) = local_rpc {
                cmd.env("ARES_FORK_RPC_URL", rpc);
            }
            let output = cmd.output().await;
            match output {
                Ok(o) => {
                    if o.status.success() {
                        info!("Shell script executed successfully.");
                        Ok(PocVerdict::Passed)
                    } else {
                        error!(
                            "Shell script failed: {}",
                            String::from_utf8_lossy(&o.stderr)
                        );
                        Ok(PocVerdict::Failed)
                    }
                }
                Err(e) => {
                    error!("Failed to execute shell script: {}", e);
                    Err(ares_core::AresError::Execution(format!(
                        "shell script failed: {}",
                        e
                    )))
                }
            }
        }
        _ => {
            error!("Unknown PoC file type: {:?}", extension);
            Err(ares_core::AresError::Execution(
                "Unknown PoC type".to_string(),
            ))
        }
    }
}

/// How many tests actually executed, summed over every libtest summary line in
/// a `cargo test` run. `None` means no summary was printed at all, i.e. nothing
/// was run — a build or link failure.
///
/// The count has to be summed across binaries rather than sniffed as a
/// substring. `cargo test <filter>` compiles and runs EVERY test target in the
/// package and hands the filter to each one, so any crate with a lib or bin
/// target — which is every Solana program crate — emits a unittest binary that
/// matches nothing and prints `running 0 tests`. That phrase therefore appears
/// precisely WHEN the PoC's own integration binary did run, and treating it as
/// "the filter matched nothing" discarded every PoC that actually executed as
/// Inconclusive. `passed + failed > 0` over all summaries answers the real
/// question: did any test run? (`ignored` deliberately does not count — an
/// `#[ignore]`d harness proves nothing either way.)
fn tests_executed(output: &str) -> Option<usize> {
    let mut total: Option<usize> = None;
    for line in output.lines() {
        let Some((_, summary)) = line.split_once("test result:") else {
            continue;
        };
        let words: Vec<&str> = summary.split_whitespace().collect();
        let ran: usize = words
            .windows(2)
            .filter(|w| matches!(w[1].trim_end_matches(';'), "passed" | "failed"))
            .filter_map(|w| w[0].parse::<usize>().ok())
            .sum();
        total = Some(total.unwrap_or(0) + ran);
    }
    total
}

/// Derive the `cargo test` filter substring for a generated PoC file.
///
/// `PocGenerator` names its harness file `<sanitized_id>_test.rs` (scan.rs) but
/// its test *functions* are `test_<sanitized_id>_<category_suffix>` (poc.rs) —
/// note the `test_` prefix, not suffix. Using the bare file stem
/// (`<sanitized_id>_test`) as the filter therefore never matches any generated
/// test name, so `cargo test` silently runs zero tests and exits success,
/// making every confirmation falsely report "Passed" regardless of the
/// finding. Stripping a trailing `_test` recovers `<sanitized_id>`, which IS a
/// substring of the real function name. Manually authored PoC files without
/// that suffix are unaffected (the strip is a no-op) — this only corrects the
/// auto-generated naming convention.
fn poc_test_filter(poc_path: &Path) -> &str {
    let stem = poc_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("ares_poc");
    stem.strip_suffix("_test").unwrap_or(stem)
}

/// Walk up from the given path to find a directory containing `Cargo.toml`.
fn find_project_root(start: &Path) -> Option<std::path::PathBuf> {
    let mut current = if start.is_file() {
        start.parent()?
    } else {
        start
    };

    loop {
        if current.join("Cargo.toml").exists() {
            return Some(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn touch_cargo_toml(dir: &TempDir) {
        let path = dir.path().join("Cargo.toml");
        std::fs::write(path, "[package]\nname = \"tmp\"\nversion = \"0.1.0\"\n").unwrap();
    }

    #[tokio::test]
    async fn run_poc_unknown_extension_errors() {
        let dir = TempDir::new().unwrap();
        let poc = dir.path().join("exploit.txt");
        std::fs::write(&poc, "not a poc").unwrap();
        let result = run_poc(&poc, dir.path(), None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_poc_sh_passed_and_failed() {
        let dir = TempDir::new().unwrap();
        touch_cargo_toml(&dir);

        let pass_script = dir.path().join("pass.sh");
        std::fs::write(&pass_script, "#!/bin/sh\nexit 0\n").unwrap();
        let verdict = run_poc(&pass_script, dir.path(), None).await.unwrap();
        assert_eq!(verdict, PocVerdict::Passed);

        let fail_script = dir.path().join("fail.sh");
        std::fs::write(&fail_script, "#!/bin/sh\nexit 1\n").unwrap();
        let verdict = run_poc(&fail_script, dir.path(), None).await.unwrap();
        assert_eq!(verdict, PocVerdict::Failed);
    }

    #[tokio::test]
    async fn run_poc_sh_receives_fork_rpc_env() {
        let dir = TempDir::new().unwrap();
        touch_cargo_toml(&dir);

        let script = dir.path().join("check_env.sh");
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "test \"$ARES_FORK_RPC_URL\" = \"http://127.0.0.1:8899\"").unwrap();
        drop(f);

        let verdict = run_poc(&script, dir.path(), Some("http://127.0.0.1:8899"))
            .await
            .unwrap();
        assert_eq!(verdict, PocVerdict::Passed);

        let verdict_missing = run_poc(&script, dir.path(), None).await.unwrap();
        assert_eq!(verdict_missing, PocVerdict::Failed);
    }

    /// Build a real, dependency-free cargo package shaped like every Solana
    /// program crate: a lib target (no unit tests of its own) plus an
    /// integration test under `tests/`. Running `cargo test <filter>` against it
    /// produces exactly the two-binary output that broke the verdict.
    fn multi_target_project(test_body: &str) -> TempDir {
        let dir = TempDir::new().unwrap();
        std::fs::write(
            dir.path().join("Cargo.toml"),
            // `[workspace]` keeps cargo from adopting any ancestor workspace.
            "[workspace]\n[package]\nname = \"victim\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/lib.rs"), "pub fn f() -> u8 { 1 }\n").unwrap();
        std::fs::create_dir_all(dir.path().join("tests")).unwrap();
        std::fs::write(
            dir.path().join("tests/ares_cross_1_test.rs"),
            format!("#[test]\nfn test_ares_cross_1_missing_signer() {{\n    {test_body}\n}}\n"),
        )
        .unwrap();
        dir
    }

    #[tokio::test]
    async fn run_poc_rs_confirms_when_the_harness_actually_ran() {
        // The lib target contributes `running 0 tests` to the combined output
        // *because* the filter matched only the PoC's own binary — i.e. exactly
        // when the PoC did run. Reading that substring as "matched nothing"
        // threw away every PoC that ran, so no finding could ever be confirmed.
        let dir = multi_target_project("assert!(true);");
        let poc = dir.path().join("tests/ares_cross_1_test.rs");
        let verdict = run_poc(&poc, dir.path(), None).await.unwrap();
        assert_eq!(verdict, PocVerdict::Passed);
    }

    #[tokio::test]
    async fn run_poc_rs_refutes_when_the_harness_ran_and_failed() {
        // The other direction: a harness whose panic carries the refutation must
        // still reach `Failed`, not be laundered into Inconclusive.
        let dir = multi_target_project("panic!(\"ARES-POC: NOT REPRODUCED\");");
        let poc = dir.path().join("tests/ares_cross_1_test.rs");
        let verdict = run_poc(&poc, dir.path(), None).await.unwrap();
        assert_eq!(verdict, PocVerdict::Failed);
    }

    #[tokio::test]
    async fn run_poc_rs_inconclusive_when_the_filter_matches_no_test() {
        // The guard that must survive: `cargo test <filter>` exits 0 when the
        // filter matches nothing, which would otherwise read as a confirmed
        // exploit produced by running no code at all.
        let dir = multi_target_project("assert!(true);");
        let poc = dir.path().join("tests/nothing_matches_this_test.rs");
        std::fs::write(&poc, "#[test]\nfn unrelated_name() {}\n").unwrap();
        let verdict = run_poc(&poc, dir.path(), None).await.unwrap();
        assert_eq!(verdict, PocVerdict::Inconclusive);
    }

    #[tokio::test]
    async fn run_poc_rs_inconclusive_when_the_harness_does_not_compile() {
        // A build failure exits non-zero exactly like a failing assertion. It is
        // absence of evidence, never a refutation.
        let dir = multi_target_project("this is not rust");
        let poc = dir.path().join("tests/ares_cross_1_test.rs");
        let verdict = run_poc(&poc, dir.path(), None).await.unwrap();
        assert_eq!(verdict, PocVerdict::Inconclusive);
    }

    #[test]
    fn tests_executed_sums_across_test_binaries() {
        // Verbatim shape of a real two-binary run: the lib unittest binary
        // matched nothing, the PoC binary ran one test.
        let output = "\
     Running unittests src/lib.rs (target/debug/deps/victim-762)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/ares_cross_1_test.rs (target/debug/deps/ares_cross_1_test-374)

running 1 test
test test_ares_cross_1_missing_signer ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        assert_eq!(tests_executed(output), Some(1));
    }

    #[test]
    fn tests_executed_distinguishes_no_run_from_empty_run() {
        // No summary at all: nothing was built, so no verdict may be read.
        assert_eq!(tests_executed("error[E0382]: borrow of moved value"), None);
        assert_eq!(tests_executed(""), None);

        // A summary that ran nothing: the filter matched no test.
        assert_eq!(
            tests_executed("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured;"),
            Some(0)
        );

        // Ignored tests did not execute, so they must not count as a run.
        assert_eq!(
            tests_executed("test result: ok. 0 passed; 0 failed; 3 ignored; 0 measured;"),
            Some(0)
        );

        // A failing run still counts as executed — that is a refutation.
        assert_eq!(
            tests_executed("test result: FAILED. 0 passed; 1 failed; 0 ignored;"),
            Some(1)
        );
    }

    #[test]
    fn poc_test_filter_strips_trailing_test_suffix() {
        // scan.rs writes "<sanitized_id>_test.rs"; the filter must be
        // "<sanitized_id>" alone to match poc.rs's "test_<sanitized_id>_*" fns.
        let path = Path::new("/out/poc/ares_cross_1_test.rs");
        assert_eq!(poc_test_filter(path), "ares_cross_1");

        let generated_fn_name = "test_ares_cross_1_missing_signer";
        assert!(generated_fn_name.contains(poc_test_filter(path)));
    }

    #[test]
    fn poc_test_filter_leaves_manual_filenames_unchanged() {
        let path = Path::new("/out/poc/exploit.rs");
        assert_eq!(poc_test_filter(path), "exploit");
    }

    #[test]
    fn find_project_root_walks_up_to_cargo_toml() {
        let dir = TempDir::new().unwrap();
        touch_cargo_toml(&dir);
        let nested = dir.path().join("a/b/c");
        std::fs::create_dir_all(&nested).unwrap();
        let poc = nested.join("poc.rs");
        std::fs::write(&poc, "// poc").unwrap();

        let root = find_project_root(&poc).unwrap();
        assert_eq!(root, dir.path());
    }

    #[test]
    fn find_project_root_none_when_no_cargo_toml() {
        let dir = TempDir::new().unwrap();
        let poc = dir.path().join("poc.rs");
        std::fs::write(&poc, "// poc").unwrap();
        assert!(find_project_root(&poc).is_none());
    }
}
