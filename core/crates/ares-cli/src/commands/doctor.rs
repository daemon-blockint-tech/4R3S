use ares_core::AresResult;
use tracing::{error, info, warn};

/// Check system dependencies and environment.
pub async fn execute() -> AresResult<()> {
    info!("=========================================");
    info!("ARES V3 Doctor — System Diagnostics");
    info!("=========================================");

    let checks = vec![
        ("cargo", "Rust / Cargo", true),
        ("rustc", "Rust Compiler", true),
        ("solana", "Solana CLI", true),
        ("solana-test-validator", "Solana Test Validator", false),
        ("anchor", "Anchor CLI", true),
        ("trident", "Trident CLI", true),
        ("docker", "Docker", false),
        ("git", "Git", true),
        ("node", "Node.js (for Anchor tests)", false),
        ("yarn", "Yarn (for Anchor tests)", false),
    ];

    let mut required_missing = 0;
    let mut optional_missing = 0;

    for (cmd, desc, required) in checks {
        match which::which(cmd) {
            Ok(path) => {
                // Try to get version
                let version_output = tokio::process::Command::new(&path)
                    .arg("--version")
                    .output()
                    .await;

                let version = match version_output {
                    Ok(v) => {
                        let s = String::from_utf8_lossy(&v.stdout);
                        s.trim().to_string()
                    }
                    Err(_) => "unknown".to_string(),
                };

                if required {
                    info!("  [OK] {}: {} ({})", desc, version, path.display());
                } else {
                    info!(
                        "  [OK] {} (optional): {} ({})",
                        desc,
                        version,
                        path.display()
                    );
                }
            }
            Err(_) => {
                if required {
                    error!(
                        "  [MISSING] {} ({}): Required but not found on PATH",
                        desc, cmd
                    );
                    required_missing += 1;
                } else {
                    warn!(
                        "  [MISSING] {} ({}): Optional, install if needed",
                        desc, cmd
                    );
                    optional_missing += 1;
                }
            }
        }
    }

    info!("=========================================");

    if required_missing > 0 {
        error!(
            "Doctor found {} required dependencies missing!",
            required_missing
        );
        info!("\nInstall missing tools:");
        info!("  - Rust: https://rustup.rs/");
        info!("  - Solana CLI: https://docs.solanalabs.com/cli/install");
        info!("  - Anchor: https://www.anchor-lang.com/docs/installation");
        info!("  - Trident: cargo install trident-cli");
        return Err(ares_core::AresError::ToolMissing(format!(
            "{} required dependencies missing",
            required_missing
        )));
    } else {
        info!("All required dependencies are available.");
    }

    if optional_missing > 0 {
        warn!("{} optional dependencies missing.", optional_missing);
        info!("Some features may be limited until optional tools are installed.");
    }

    // Check Docker daemon
    let docker_running = tokio::process::Command::new("docker")
        .args(["info"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    if docker_running {
        info!("Docker daemon is running.");
    } else {
        warn!("Docker daemon is not running or not accessible. Sandbox features will be limited.");
    }

    info!("Doctor check complete.");
    Ok(())
}
