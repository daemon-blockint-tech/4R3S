//! A `--fuzz false` scan must not depend on the fuzzer, and must not claim it.
//!
//! ORC2-F1: `check_trident_installation()` and `TridentTool::new()` both ran
//! before the `if fuzz` gate that decides whether the fuzzer is used at all, so
//! `ares scan --fuzz false` aborted with
//!
//!     Error: External tool missing: trident-cli not found.
//!
//! before any analysis. The flag skipped the fuzzing WORK but not the fuzzing
//! PREREQUISITE, which made a static-only scan impossible anywhere without a
//! fuzzer installed — CI, a container, and the 159-target eval reproduction that
//! `eval/predictions/README.md` documents as `--fuzz false`.
//!
//! The report's own comment already claimed `tools_used` held "only tools
//! actually executed during this scan" while listing trident unconditionally, so
//! every static report also named a stage that never ran.
//!
//! This test pins the observable half — a real scan of a real program, through
//! the real `execute`, asserting the emitted provenance. PATH-independence was
//! verified separately by moving `~/.cargo/bin/trident` aside and re-running:
//! before the fix the scan aborted on the missing binary, after it the scan
//! completed and wrote a report.

use std::path::PathBuf;

/// Removes the scratch tree on the way out, including on panic.
///
/// A trailing `remove_dir_all` does not run when an assertion fires, and this
/// test writes inside the crate directory (see the note at `root` below), so a
/// failing run would leave `.ares-orc2f1-<pid>/` behind for `git status` to
/// report as untracked.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_program(root: &std::path::Path, body: &str) {
    let src = root.join("src");
    std::fs::create_dir_all(&src).expect("create src");
    std::fs::write(src.join("lib.rs"), body).expect("write lib.rs");
}

fn config(output: &std::path::Path) -> ares_core::AresConfig {
    ares_core::AresConfig {
        output_dir: output.to_path_buf(),
        // A path that cannot exist. `TridentTool::new` checks `exists()`, so if
        // the scan still constructs the tool with fuzzing off, this fails the
        // scan outright — which is precisely the regression being guarded.
        trident_path: Some(PathBuf::from("/nonexistent/ares-test/trident")),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_static_scan_does_not_need_the_fuzzer_and_does_not_claim_it() {
    // Under the working directory, not /tmp: ares-policy's default sandbox is
    // `allowed_read_paths: ["."]`, so a target outside cwd is refused before the
    // mapper opens it and the scan fails for a reason unrelated to this test.
    let root = std::env::current_dir()
        .expect("cwd")
        .join(format!(".ares-orc2f1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let _scratch = Scratch(root.clone());
    let target = root.join("program");
    let output = root.join("out");
    write_program(
        &target,
        "pub fn process_instruction(\n\
         \x20   program_id: &Pubkey,\n\
         \x20   accounts: &[AccountInfo],\n\
         ) -> ProgramResult {\n\
         \x20   let acct = next_account_info(&mut accounts.iter())?;\n\
         \x20   let state = State::try_from_slice(&acct.data.borrow())?;\n\
         \x20   Ok(())\n\
         }\n",
    );

    let result = ares_v3::commands::scan::execute(
        &target,
        &config(&output),
        None,
        false, // full_pipeline
        false, // fuzz — the flag under test
        false, // poc
        60,
        &output,
    )
    .await;

    assert!(
        result.is_ok(),
        "a static scan must not require the fuzzer: {:?}",
        result.err()
    );

    let report_path = std::fs::read_dir(&output)
        .expect("output dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .expect("a report was written");

    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&report_path).expect("read report"))
            .expect("report is JSON");
    let meta = &report["metadata"];

    let tools = meta["tools_used"].as_array().expect("tools_used array");
    assert!(
        tools.is_empty(),
        "no fuzzer ran, so none may be reported as used: {tools:?}"
    );

    let pipeline: Vec<&str> = meta["agent_pipeline"]
        .as_array()
        .expect("agent_pipeline array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        !pipeline.contains(&"FuzzerOrchestrator"),
        "the fuzzer stage did not run and must not be listed: {pipeline:?}"
    );
    // The stages that DID run still have to be named, or the fix would pass by
    // emptying the field rather than by telling the truth.
    assert!(
        pipeline.contains(&"Mapper") && pipeline.contains(&"Triager"),
        "stages that ran must still be reported: {pipeline:?}"
    );
}

/// ORC2-F6: scanning a path that does not exist wrote a fully-formed report —
/// exit 0, `findings: []`, an all-zero summary, and a `target.name` taken from
/// the last path segment. Indistinguishable from a genuine clean audit.
#[tokio::test]
async fn a_missing_target_is_an_error_not_a_clean_report() {
    let root = std::env::current_dir()
        .expect("cwd")
        .join(format!(".ares-orc2f6a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let _scratch = Scratch(root.clone());
    let output = root.join("out");
    std::fs::create_dir_all(&output).expect("create out");

    let missing = root.join("no-such-program");
    let result = ares_v3::commands::scan::execute(
        &missing,
        &config(&output),
        None,
        false,
        false,
        false,
        60,
        &output,
    )
    .await;

    assert!(
        result.is_err(),
        "a target that does not exist must not scan cleanly"
    );
    assert_eq!(
        std::fs::read_dir(&output)
            .expect("out dir")
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .count(),
        0,
        "no report may be written for a target that was never read"
    );
}

/// The same false all-clear by a different route: the directory exists but
/// holds no `programs/` or `src/`. `MapperAgent::analyze` only `warn!`s and
/// returns an empty graph, and a warning is not part of the contract a caller
/// consumes — so the scan completed and reported the target clean.
#[tokio::test]
async fn a_target_with_no_source_root_is_an_error_not_a_clean_report() {
    let root = std::env::current_dir()
        .expect("cwd")
        .join(format!(".ares-orc2f6b-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let _scratch = Scratch(root.clone());
    let target = root.join("program");
    let output = root.join("out");
    // Exists, and even holds Rust — but not where the mapper looks.
    std::fs::create_dir_all(&target).expect("create target");
    std::fs::write(target.join("lib.rs"), "pub fn f() {}\n").expect("write stray rs");
    std::fs::create_dir_all(&output).expect("create out");

    let result = ares_v3::commands::scan::execute(
        &target,
        &config(&output),
        None,
        false,
        false,
        false,
        60,
        &output,
    )
    .await;

    assert!(
        result.is_err(),
        "a target with no source root must not scan cleanly"
    );
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        err.contains("programs/") || err.contains("src/"),
        "the error must say what was expected, or the caller cannot act on it: {err}"
    );
}
