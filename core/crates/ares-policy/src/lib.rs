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
    /// Both the target and the configured boundary paths are canonicalized
    /// (`~` expanded, `.`/`..` resolved, made absolute) before comparison, and
    /// the decision is default-deny: a target matching no allowed read path is
    /// rejected even if it also matches no blocked path.
    pub fn check_scan_permission(&self, target_path: &Path) -> AresResult<()> {
        let target = canonicalize_policy_path(target_path);
        let target_str = target.to_string_lossy();

        // Blocked paths take precedence over every allow rule.
        let blocked = self
            .sandbox_boundary
            .blocked_paths
            .iter()
            .map(|p| canonicalize_policy_path(p))
            .any(|b| target.starts_with(&b));

        if blocked {
            error!("POLICY VIOLATION: Scanning blocked path: {}", target_str);
            return Err(AresError::PolicyViolation(format!(
                "Scanning blocked path: {}",
                target_str
            )));
        }

        // Default-deny: the target must sit under an explicitly allowed read path.
        let allowed = self
            .sandbox_boundary
            .allowed_read_paths
            .iter()
            .map(|p| canonicalize_policy_path(p))
            .any(|a| target.starts_with(&a));

        if !allowed {
            error!(
                "POLICY VIOLATION: Path outside allowed read paths: {}",
                target_str
            );
            return Err(AresError::PolicyViolation(format!(
                "Path is outside the allowed read paths: {}",
                target_str
            )));
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

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if s == "~" || s.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            let rest = s.strip_prefix('~').unwrap_or("").trim_start_matches('/');
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

/// Canonicalize a policy path without touching the filesystem: expand `~`,
/// make it absolute against the current directory, and lexically resolve
/// `.` / `..` components (works for paths that do not exist).
fn canonicalize_policy_path(path: &Path) -> PathBuf {
    let expanded = expand_tilde(path);
    let absolute = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("/"))
            .join(expanded)
    };

    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }

    // Lexical normalisation alone does not make this path safe to compare against
    // the sandbox roots. It rewrites `..` textually and never touches symlinks, so
    // a link *inside* the sandbox reads anything on the host: an audited
    // repository containing `docs/config.rs -> /Users/victim/.ssh/id_rsa`
    // normalises to `<cwd>/docs/config.rs`, which `starts_with` the allowed root,
    // and the subsequent `fs::read_to_string` follows the link. Git stores and
    // checks out symlinks, so the repository under audit chooses this.
    //
    // `fs::canonicalize` resolves every link, but fails outright on a path that
    // does not exist yet — and write destinations legitimately do not. So resolve
    // the deepest ancestor that *does* exist and re-attach the remainder: the
    // existing part is where a symlink could hide, and the missing tail cannot
    // redirect anything.
    let mut prefix: &Path = &normalized;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = prefix.canonicalize() {
            let mut resolved = real;
            for component in tail.iter().rev() {
                resolved.push(component);
            }
            return resolved;
        }
        match (prefix.file_name(), prefix.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                prefix = parent;
            }
            // Reached the root without resolving anything (or the path has no
            // parent). Fall back to the lexical form — it is no worse than before
            // and cannot silently widen access, because a path that resolves to
            // nothing still has to pass the allow-list check below.
            _ => return normalized,
        }
    }
}

#[cfg(test)]
mod symlink_escape_tests {
    use super::*;
    use std::fs;

    /// A symlink inside the sandbox must not become a read of the link target.
    ///
    /// The audited repository controls its own files, and git checks symlinks out
    /// verbatim, so `docs/config.rs -> ~/.ssh/id_rsa` is a file the target ships.
    /// With lexical-only normalisation the policy saw `<sandbox>/docs/config.rs`,
    /// allowed it, and the read followed the link off the sandbox entirely.
    #[test]
    #[cfg(unix)]
    fn a_symlink_out_of_the_sandbox_is_rejected() {
        let tmp = std::env::temp_dir().join(format!("ares-policy-{}", std::process::id()));
        let sandbox = tmp.join("sandbox");
        let secret_dir = tmp.join("outside");
        fs::create_dir_all(&sandbox).unwrap();
        fs::create_dir_all(&secret_dir).unwrap();
        let secret = secret_dir.join("id_rsa");
        fs::write(&secret, b"PRIVATE KEY").unwrap();

        let link = sandbox.join("config.rs");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let resolved = canonicalize_policy_path(&link);
        let allowed = canonicalize_policy_path(&sandbox);

        assert!(
            !resolved.starts_with(&allowed),
            "symlink escaped the sandbox: {resolved:?} still matched {allowed:?}"
        );
        fs::remove_dir_all(&tmp).ok();
    }

    /// The other direction: resolving links must not break ordinary allowed reads.
    #[test]
    fn a_real_file_inside_the_sandbox_is_still_allowed() {
        let tmp = std::env::temp_dir().join(format!("ares-policy-ok-{}", std::process::id()));
        let sandbox = tmp.join("sandbox");
        fs::create_dir_all(&sandbox).unwrap();
        let real = sandbox.join("lib.rs");
        fs::write(&real, b"fn main() {}").unwrap();

        assert!(canonicalize_policy_path(&real).starts_with(canonicalize_policy_path(&sandbox)));
        fs::remove_dir_all(&tmp).ok();
    }

    /// Write destinations do not exist yet; `canonicalize` fails on them, so the
    /// deepest-existing-ancestor fallback has to keep them inside the sandbox.
    #[test]
    fn a_not_yet_created_file_resolves_inside_its_existing_parent() {
        let tmp = std::env::temp_dir().join(format!("ares-policy-new-{}", std::process::id()));
        let sandbox = tmp.join("sandbox");
        fs::create_dir_all(&sandbox).unwrap();
        let unborn = sandbox.join("nested/does-not-exist.json");

        assert!(canonicalize_policy_path(&unborn).starts_with(canonicalize_policy_path(&sandbox)));
        fs::remove_dir_all(&tmp).ok();
    }

    /// `..` must not climb out even when every component exists.
    #[test]
    fn parent_traversal_leaves_the_sandbox_visibly() {
        let tmp = std::env::temp_dir().join(format!("ares-policy-dd-{}", std::process::id()));
        let sandbox = tmp.join("sandbox");
        fs::create_dir_all(sandbox.join("sub")).unwrap();
        let escaped = sandbox.join("sub/../../outside.txt");

        assert!(!canonicalize_policy_path(&escaped).starts_with(canonicalize_policy_path(&sandbox)));
        fs::remove_dir_all(&tmp).ok();
    }
}
