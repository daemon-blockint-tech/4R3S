use ares_core::AresResult;
use tracing::{error, info};

/// Show current policy status.
pub async fn status() -> AresResult<()> {
    info!("ARES Policy Engine Status");
    info!("=========================");

    // Phase 1: Load and display policy
    let policy_file = std::path::PathBuf::from("ares-policy.toml");
    if policy_file.exists() {
        info!("Policy file: {:?}", policy_file);
        let content = tokio::fs::read_to_string(&policy_file).await?;
        info!("Policy loaded successfully.");
        info!("\nCurrent capabilities:");

        // Parse and display key sections
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                info!("  Section: {}", trimmed);
            }
            if trimmed.starts_with("allow") || trimmed.starts_with("deny") {
                info!("    {}", trimmed);
            }
        }
    } else {
        error!("Policy file not found: {:?}", policy_file);
        info!("Run 'ares init' to create default policy.");
    }

    Ok(())
}

/// Request capability escalation.
pub async fn escalate(capability: &str) -> AresResult<()> {
    info!("ARES Capability Escalation Request");
    info!("Capability: {}", capability);

    // Phase 1: Simulate human approval gate
    info!("\n========================================");
    info!("POLICY ESCALATION REQUIRED");
    info!("========================================");
    info!(
        "Capability '{}' requires explicit human approval.",
        capability
    );
    info!("This is an IronCurtain-style safety guardrail.");
    info!("");
    info!("To approve, run: ares policy approve {}", capability);
    info!("To deny, run: ares policy deny {}", capability);
    info!("");
    info!("Current status: PENDING_APPROVAL");

    Ok(())
}

/// Reset policy to default.
pub async fn reset() -> AresResult<()> {
    info!("Resetting ARES policy to defaults...");

    let default_policy = include_str!("../../../../ares-policy.toml.template");
    let policy_path = std::path::PathBuf::from("ares-policy.toml");
    tokio::fs::write(&policy_path, default_policy).await?;

    info!("Policy reset to defaults: {:?}", policy_path);
    info!("Review and modify before use.");

    Ok(())
}
