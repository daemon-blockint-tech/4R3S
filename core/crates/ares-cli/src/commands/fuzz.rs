use ares_core::AresResult;
use ares_trident::TridentTool;
use std::path::Path;
use tracing::info;

/// Run fuzzing campaign with Trident.
pub async fn execute(
    path: &Path,
    iterations: u64,
    test: Option<String>,
    deterministic: bool,
) -> AresResult<()> {
    info!("ARES Fuzz Campaign");
    info!(
        "Target: {:?} | Iterations: {} | Deterministic: {}",
        path, iterations, deterministic
    );

    let trident = TridentTool::new(None)?;
    let trident = trident.with_working_dir(path.to_path_buf());

    let targets = if let Some(t) = test {
        vec![t]
    } else {
        // Discover all fuzz targets
        let fuzz_dir = path.join("trident-tests/fuzz_tests");
        if !fuzz_dir.exists() {
            info!("No fuzz tests found. Run 'ares init' first.");
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(&fuzz_dir).await?;
        let mut targets = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                    targets.push(stem.to_string());
                }
            }
        }
        targets
    };

    for target in targets {
        info!(
            "Running fuzz target: {} ({} iterations)",
            target, iterations
        );
        let result = trident.fuzz_run(&target, iterations, 3600).await?;

        if result.success {
            info!(
                "  [PASS] {} — no crashes after {} iterations",
                target, result.iterations_ran
            );
        } else {
            info!(
                "  [FAIL] {} — {} crashes, {} invariant violations",
                target,
                result.crashes.len(),
                result.invariant_violations.len()
            );
            for crash in &result.crashes {
                info!("    Crash: {}", crash);
            }
        }
    }

    Ok(())
}
