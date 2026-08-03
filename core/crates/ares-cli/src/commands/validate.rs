use ares_core::AresConfig;
use ares_core::AresResult;
use std::path::Path;
use tracing::{error, info};

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

    let extension = poc_path.extension().and_then(|e| e.to_str());

    let result = match extension {
        Some("rs") => {
            info!("Detected Rust test file. Building and running via cargo test in SVM...");

            let test_filter = poc_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("ares_poc");

            let mut cmd = tokio::process::Command::new("cargo");
            cmd.current_dir(&project_root)
                .args(["test", test_filter, "--", "--nocapture"]);
            if let Some(ref rpc) = local_rpc {
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
                    if o.status.success() {
                        info!("PoC validation PASSED — program may be VULNERABLE (transaction succeeded).");
                    } else {
                        info!("PoC validation produced failures — program may be SECURE, or test needs adjustment.");
                    }
                    Ok(())
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
            cmd.current_dir(&project_root)
                .args(["test", "--skip-build"]);
            if let Some(ref rpc) = local_rpc {
                cmd.env("ANCHOR_PROVIDER_URL", rpc);
            }
            let output = cmd.output().await;
            match output {
                Ok(o) => {
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    if o.status.success() {
                        info!("Anchor test completed successfully.");
                        info!("{}", stdout.lines().take(20).collect::<Vec<_>>().join("\n"));
                    } else {
                        error!("Anchor test failed.");
                        error!("{}", String::from_utf8_lossy(&o.stderr));
                    }
                    Ok(())
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
            cmd.current_dir(&project_root).arg(poc_path);
            if let Some(ref rpc) = local_rpc {
                cmd.env("ARES_FORK_RPC_URL", rpc);
            }
            let output = cmd.output().await;
            match output {
                Ok(o) => {
                    if o.status.success() {
                        info!("Shell script executed successfully.");
                    } else {
                        error!(
                            "Shell script failed: {}",
                            String::from_utf8_lossy(&o.stderr)
                        );
                    }
                    Ok(())
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
    };

    // Phase 8: Stop validator if it was started
    if let Some(validator) = validator_handle {
        validator.stop().await;
        info!("Fork validator stopped.");
    }

    result
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
