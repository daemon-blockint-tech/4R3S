use ares_core::AresResult;
use std::path::Path;
use tracing::{info, warn};

/// Initialize ARES workspace in the given directory.
/// Creates config files, output directories, and verifies system dependencies.
pub async fn execute(path: &Path) -> AresResult<()> {
    info!("Initializing ARES workspace at: {:?}", path);

    // Create output directories
    let output_dir = path.join("ares-output");
    let reports_dir = output_dir.join("reports");
    let artifacts_dir = output_dir.join("artifacts");
    let poc_dir = output_dir.join("poc");
    let benchmark_dir = output_dir.join("benchmark");

    tokio::fs::create_dir_all(&output_dir).await?;
    tokio::fs::create_dir_all(&reports_dir).await?;
    tokio::fs::create_dir_all(&artifacts_dir).await?;
    tokio::fs::create_dir_all(&poc_dir).await?;
    tokio::fs::create_dir_all(&benchmark_dir).await?;

    info!("Created output directories under {:?}", output_dir);

    // Create default config file if not exists
    let config_path = path.join("ares.toml");
    if !config_path.exists() {
        let default_config = include_str!("../../../../ares.toml.template");
        tokio::fs::write(&config_path, default_config).await?;
        info!("Created default config: {:?}", config_path);
    } else {
        warn!("Config already exists: {:?}", config_path);
    }

    // Create default policy file if not exists
    let policy_path = path.join("ares-policy.toml");
    if !policy_path.exists() {
        let default_policy = include_str!("../../../../ares-policy.toml.template");
        tokio::fs::write(&policy_path, default_policy).await?;
        info!("Created default policy: {:?}", policy_path);
    } else {
        warn!("Policy already exists: {:?}", policy_path);
    }

    // Verify system dependencies
    info!("Verifying system dependencies...");
    let checks = vec![
        ("cargo", "Rust toolchain"),
        ("rustc", "Rust compiler"),
        ("solana", "Solana CLI"),
        ("anchor", "Anchor CLI"),
        ("trident", "Trident CLI"),
        ("docker", "Docker (for sandbox)"),
        ("git", "Git"),
    ];

    for (cmd, desc) in checks {
        match which::which(cmd) {
            Ok(path) => info!("  [OK] {} found at {:?}", desc, path),
            Err(_) => warn!("  [MISSING] {} ({}) not found on PATH", desc, cmd),
        }
    }

    info!("ARES workspace initialized successfully.");
    info!("Next steps:");
    info!("  1. Review and edit ares.toml configuration");
    info!("  2. Review ares-policy.toml capability policy");
    info!("  3. Run 'ares scan <program-path>' to start auditing");

    Ok(())
}
