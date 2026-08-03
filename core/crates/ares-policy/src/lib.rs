use ares_core::{AresError, AresResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

/// IronCurtain-style policy engine for ARES V3.
///
/// Inspired by IronCurtain.dev (Niels Provos):
/// - Least privilege: agent may only access resources explicitly permitted
/// - No destruction: delete operations outside sandbox never permitted
/// - Human oversight: operations outside sandbox require explicit human approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEngine {
    pub constitution: Constitution,
    pub capabilities: HashMap<String, CapabilityLevel>,
    pub sandbox_boundary: SandboxBoundary,
    pub audit_log: Vec<PolicyDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constitution {
    pub name: String,
    pub version: String,
    pub principles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityLevel {
    pub action: String,
    pub level: PermissionLevel,
    pub requires_approval: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum PermissionLevel {
    Allow,
    Deny,
    Escalate,
    SandboxOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxBoundary {
    pub allowed_read_paths: Vec<PathBuf>,
    pub allowed_write_paths: Vec<PathBuf>,
    pub allowed_exec_paths: Vec<PathBuf>,
    pub blocked_paths: Vec<PathBuf>,
    pub allow_network: bool,
    pub allow_git_remote: bool,
    pub allow_mainnet_interaction: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub timestamp: String,
    pub action: String,
    pub target: String,
    pub decision: String,
    pub reason: String,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        let mut capabilities = HashMap::new();

        // Filesystem capabilities
        capabilities.insert(
            "fs.read".to_string(),
            CapabilityLevel {
                action: "fs.read".to_string(),
                level: PermissionLevel::Allow,
                requires_approval: false,
                description: "Read files within project directory".to_string(),
            },
        );
        capabilities.insert(
            "fs.write".to_string(),
            CapabilityLevel {
                action: "fs.write".to_string(),
                level: PermissionLevel::SandboxOnly,
                requires_approval: false,
                description: "Write files only in sandbox output directory".to_string(),
            },
        );
        capabilities.insert(
            "fs.delete".to_string(),
            CapabilityLevel {
                action: "fs.delete".to_string(),
                level: PermissionLevel::SandboxOnly,
                requires_approval: true,
                description: "Delete files only within sandbox".to_string(),
            },
        );

        // Git capabilities
        capabilities.insert(
            "git.status".to_string(),
            CapabilityLevel {
                action: "git.status".to_string(),
                level: PermissionLevel::Allow,
                requires_approval: false,
                description: "Read-only git operations (status, diff, log)".to_string(),
            },
        );
        capabilities.insert(
            "git.commit".to_string(),
            CapabilityLevel {
                action: "git.commit".to_string(),
                level: PermissionLevel::Escalate,
                requires_approval: true,
                description: "Commit changes to local repository".to_string(),
            },
        );
        capabilities.insert(
            "git.push".to_string(),
            CapabilityLevel {
                action: "git.push".to_string(),
                level: PermissionLevel::Deny,
                requires_approval: true,
                description: "Push to remote repository — REQUIRES EXPLICIT APPROVAL".to_string(),
            },
        );

        // Network capabilities
        capabilities.insert(
            "network.fetch".to_string(),
            CapabilityLevel {
                action: "network.fetch".to_string(),
                level: PermissionLevel::Allow,
                requires_approval: false,
                description: "Fetch web content from allowed domains".to_string(),
            },
        );
        capabilities.insert(
            "network.scan_remote".to_string(),
            CapabilityLevel {
                action: "network.scan_remote".to_string(),
                level: PermissionLevel::Deny,
                requires_approval: true,
                description: "Scan third-party contracts on public network — DENIED".to_string(),
            },
        );

        // Solana capabilities
        capabilities.insert(
            "solana.local_test".to_string(),
            CapabilityLevel {
                action: "solana.local_test".to_string(),
                level: PermissionLevel::Allow,
                requires_approval: false,
                description: "Run tests on local validator".to_string(),
            },
        );
        capabilities.insert(
            "solana.mainnet_fork".to_string(),
            CapabilityLevel {
                action: "solana.mainnet_fork".to_string(),
                level: PermissionLevel::Escalate,
                requires_approval: true,
                description: "Fork mainnet for simulation — REQUIRES APPROVAL".to_string(),
            },
        );
        capabilities.insert(
            "solana.mainnet_deploy".to_string(),
            CapabilityLevel {
                action: "solana.mainnet_deploy".to_string(),
                level: PermissionLevel::Deny,
                requires_approval: true,
                description: "Deploy to mainnet — NEVER ALLOWED for audit agent".to_string(),
            },
        );

        // Exploit capabilities
        capabilities.insert(
            "exploit.local_poc".to_string(),
            CapabilityLevel {
                action: "exploit.local_poc".to_string(),
                level: PermissionLevel::Allow,
                requires_approval: false,
                description: "Generate and run PoC in sandbox environment".to_string(),
            },
        );
        capabilities.insert(
            "exploit.mainnet_execute".to_string(),
            CapabilityLevel {
                action: "exploit.mainnet_execute".to_string(),
                level: PermissionLevel::Deny,
                requires_approval: true,
                description: "Execute exploit on mainnet — NEVER ALLOWED".to_string(),
            },
        );
        capabilities.insert(
            "exploit.third_party_scan".to_string(),
            CapabilityLevel {
                action: "exploit.third_party_scan".to_string(),
                level: PermissionLevel::Deny,
                requires_approval: true,
                description: "Scan contracts not owned by user — DENIED".to_string(),
            },
        );

        Self {
            constitution: Constitution {
                name: "ARES V3 Security Constitution".to_string(),
                version: "1.0".to_string(),
                principles: vec![
                    "Least privilege: agent may only access resources explicitly permitted by policy.".to_string(),
                    "No destruction: delete operations outside the sandbox are never permitted.".to_string(),
                    "Human oversight: operations outside the sandbox require explicit human approval.".to_string(),
                    "Defensive use only: exploit generation is restricted to user's own programs.".to_string(),
                    "Audit everything: all agent actions are logged for security review.".to_string(),
                ],
            },
            capabilities,
            sandbox_boundary: SandboxBoundary {
                allowed_read_paths: vec![PathBuf::from(".")],
                allowed_write_paths: vec![PathBuf::from("ares-output")],
                allowed_exec_paths: vec![],
                blocked_paths: vec![
                    PathBuf::from("~/.ssh"),
                    PathBuf::from("~/.aws"),
                    PathBuf::from("~/.config/solana/id.json"),
                    PathBuf::from("/etc"),
                    PathBuf::from("/proc"),
                ],
                allow_network: true,
                allow_git_remote: false,
                allow_mainnet_interaction: false,
            },
            audit_log: Vec::new(),
        }
    }
}

impl PolicyEngine {
    /// Load policy from TOML file, or use defaults.
    pub fn new(policy_file: Option<&Path>) -> AresResult<Self> {
        if let Some(path) = policy_file {
            if path.exists() {
                info!("Loading policy from: {:?}", path);
                let content = std::fs::read_to_string(path).map_err(|e| {
                    AresError::PolicyViolation(format!("Failed to read policy: {}", e))
                })?;
                let engine: PolicyEngine = toml::from_str(&content).map_err(|e| {
                    AresError::PolicyViolation(format!("Failed to parse policy: {}", e))
                })?;
                info!(
                    "Policy loaded: {} v{}",
                    engine.constitution.name, engine.constitution.version
                );
                return Ok(engine);
            }
        }

        warn!("No policy file found, using default ARES security policy.");
        Ok(PolicyEngine::default())
    }

    /// Check if scanning a target program is allowed.
    pub fn check_scan_permission(&self, target_path: &Path) -> AresResult<()> {
        let target_str = target_path.to_string_lossy();

        // Check if target is within allowed boundaries
        let allowed = self
            .sandbox_boundary
            .allowed_read_paths
            .iter()
            .any(|p| target_str.starts_with(&p.to_string_lossy().to_string()));

        if !allowed {
            // Check if it's explicitly blocked
            let blocked = self
                .sandbox_boundary
                .blocked_paths
                .iter()
                .any(|p| target_str.contains(&p.to_string_lossy().to_string()));

            if blocked {
                error!("POLICY VIOLATION: Scanning blocked path: {}", target_str);
                return Err(AresError::PolicyViolation(format!(
                    "Scanning blocked path: {}",
                    target_str
                )));
            }
        }

        info!("Policy check passed: scan authorized for {}", target_str);
        Ok(())
    }

    /// Check if a specific capability is allowed.
    pub fn check_capability(&self, action: &str) -> AresResult<PermissionLevel> {
        match self.capabilities.get(action) {
            Some(cap) => match cap.level {
                PermissionLevel::Allow => {
                    info!("Capability '{}' allowed: {}", action, cap.description);
                    Ok(PermissionLevel::Allow)
                }
                PermissionLevel::SandboxOnly => {
                    info!("Capability '{}' sandbox-only: {}", action, cap.description);
                    Ok(PermissionLevel::SandboxOnly)
                }
                PermissionLevel::Escalate => {
                    warn!(
                        "Capability '{}' requires escalation: {}",
                        action, cap.description
                    );
                    Ok(PermissionLevel::Escalate)
                }
                PermissionLevel::Deny => {
                    error!("Capability '{}' denied: {}", action, cap.description);
                    Err(AresError::PolicyViolation(format!(
                        "Action '{}' is denied by policy: {}",
                        action, cap.description
                    )))
                }
            },
            None => {
                // Default deny for unknown capabilities
                warn!("Unknown capability '{}', defaulting to deny", action);
                Err(AresError::PolicyViolation(format!(
                    "Unknown capability '{}': default deny",
                    action
                )))
            }
        }
    }

    /// Log a policy decision.
    pub fn log_decision(&mut self, action: &str, target: &str, decision: &str, reason: &str) {
        let log_entry = PolicyDecision {
            timestamp: chrono::Utc::now().to_rfc3339(),
            action: action.to_string(),
            target: target.to_string(),
            decision: decision.to_string(),
            reason: reason.to_string(),
        };
        self.audit_log.push(log_entry);
    }
}
