use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{sleep, timeout, Duration};
use tracing::{info, warn};

/// Manages a `solana-test-validator` process forked from mainnet with `--clone`.
///
/// Lifecycle:
/// 1. `ForkValidator::builder(rpc_url)` — configure accounts/slot/program.
/// 2. `start().await` — spawns validator, waits for RPC ready.
/// 3. Run tests / scripts against `http://127.0.0.1:8899`.
/// 4. `stop().await` — kills process and waits for cleanup.
pub struct ForkValidator {
    rpc_url: String,
    clone_accounts: Vec<String>,
    program_id: Option<String>,
    program_so: Option<PathBuf>,
    slot: Option<u64>,
    local_rpc: String,
    process: Option<tokio::process::Child>,
}

impl ForkValidator {
    /// Create a builder for configuring the fork validator.
    pub fn builder(rpc_url: impl Into<String>) -> ForkValidatorBuilder {
        ForkValidatorBuilder::new(rpc_url)
    }

    /// Start the validator and return the local RPC URL when ready.
    /// Uses `kill_on_drop(true)` as a safety net; call `stop()` explicitly for clean shutdown.
    pub async fn start(&mut self) -> Result<String, String> {
        let mut cmd = Command::new("solana-test-validator");
        cmd.arg("--url")
            .arg(&self.rpc_url)
            .arg("--rpc-port")
            .arg("8899")
            .arg("--reset")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if let Some(slot) = self.slot {
            cmd.arg("--slot").arg(slot.to_string());
        }

        for acc in &self.clone_accounts {
            cmd.arg("--clone").arg(acc);
        }

        if let (Some(pid), Some(ref so)) = (&self.program_id, &self.program_so) {
            cmd.arg("--bpf-program").arg(pid).arg(so);
        }

        info!("Starting solana-test-validator: {:?}", cmd.as_std());

        let mut child = cmd.spawn().map_err(|e| {
            format!(
                "Failed to start solana-test-validator: {}. Is it installed?",
                e
            )
        })?;

        let stdout = child
            .stdout
            .take()
            .ok_or("Failed to capture validator stdout")?;
        let mut reader = BufReader::new(stdout).lines();

        // Wait for startup message in stdout ("RPC service" or "health check")
        let startup = timeout(Duration::from_secs(60), async {
            while let Some(line) = reader.next_line().await.ok().flatten() {
                info!("[validator] {}", line);
                if line.contains("RPC service") || line.contains("health check") {
                    return true;
                }
            }
            false
        })
        .await;

        match startup {
            Ok(true) => {
                // Give RPC a moment to fully bind
                sleep(Duration::from_secs(2)).await;
                self.process = Some(child);
                Ok(self.local_rpc.clone())
            }
            Ok(false) => {
                let _ = child.kill().await;
                Err("solana-test-validator exited without starting RPC".to_string())
            }
            Err(_) => {
                let _ = child.kill().await;
                Err("solana-test-validator startup timed out after 60s".to_string())
            }
        }
    }

    /// Stop the validator process gracefully.
    pub async fn stop(mut self) {
        if let Some(mut child) = self.process.take() {
            info!("Stopping solana-test-validator...");
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
    }
}

impl Drop for ForkValidator {
    fn drop(&mut self) {
        if self.process.is_some() {
            warn!("ForkValidator dropped without explicit stop; process will be killed via kill_on_drop");
        }
    }
}

/// Builder for [`ForkValidator`].
pub struct ForkValidatorBuilder {
    rpc_url: String,
    clone_accounts: Vec<String>,
    program_id: Option<String>,
    program_so: Option<PathBuf>,
    slot: Option<u64>,
}

impl ForkValidatorBuilder {
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            clone_accounts: Vec::new(),
            program_id: None,
            program_so: None,
            slot: None,
        }
    }

    pub fn clone_accounts(mut self, accounts: Vec<String>) -> Self {
        self.clone_accounts = accounts;
        self
    }

    pub fn program(mut self, program_id: String, program_so: PathBuf) -> Self {
        self.program_id = Some(program_id);
        self.program_so = Some(program_so);
        self
    }

    pub fn slot(mut self, slot: Option<u64>) -> Self {
        self.slot = slot;
        self
    }

    pub fn build(self) -> ForkValidator {
        ForkValidator {
            rpc_url: self.rpc_url,
            clone_accounts: self.clone_accounts,
            program_id: self.program_id,
            program_so: self.program_so,
            slot: self.slot,
            local_rpc: "http://127.0.0.1:8899".to_string(),
            process: None,
        }
    }
}
