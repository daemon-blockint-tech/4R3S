use anyhow::Result;
use ares_core::AresConfig;
use ares_v3::ReportFormat;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::{info, warn};

/// ARES V3 — Autonomous Solana Security Auditor
/// Designed to exceed Trident Arena benchmarks across every dimension.
#[derive(Parser, Debug)]
#[command(name = "ares", about, version, long_about = None)]
struct Cli {
    /// Path to ARES configuration file
    #[arg(short, long, value_name = "FILE", default_value = "ares.toml")]
    config: PathBuf,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Policy override: require explicit approval for dangerous operations
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    strict_policy: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the interactive Agentic TUI (REPL)
    Interact {},

    /// Initialize ARES workspace and verify dependencies
    Init {
        /// Project directory to initialize
        #[arg(default_value = ".")]
        path: PathBuf,
    },

    /// Run a security scan on a Solana program
    Scan {
        /// Path to the Solana program (Anchor project directory)
        #[arg(value_name = "PATH")]
        program_path: PathBuf,

        /// Scan only specific file or module
        #[arg(short, long)]
        target: Option<String>,

        /// Enable full multi-agent pipeline (Mapper -> Hypothesis -> Fuzzer -> Exploit -> Triager -> Reporter)
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        full_pipeline: bool,

        /// Run property-based fuzzing with Trident
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        fuzz: bool,

        /// Generate deterministic proof-of-concept tests for each finding
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        poc: bool,

        /// Merge ares-mapper's AST-based scanner findings (Anchor/Solitaire
        /// constraint checks, taint-tracked sinks) into this scan's report.
        /// Defaults to false: this detection path has never been measured
        /// against a real corpus at scale, unlike the hypothesis pipeline
        /// (EVAL-3 measured F1 0.3007). Opt in explicitly to start gathering
        /// that evidence; flip the default once it's justified, not before.
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        ast_scan: bool,

        /// Maximum scan duration in seconds
        #[arg(long, default_value = "3600")]
        max_duration: u64,

        /// Output directory for reports and artifacts
        #[arg(short, long, default_value = "./ares-output")]
        output: PathBuf,
    },

    /// Run fuzzing campaign with Trident
    Fuzz {
        /// Path to the fuzz test or program
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Number of fuzz iterations
        #[arg(short, long, default_value = "100000")]
        iterations: u64,

        /// Specific fuzz test name to run
        #[arg(short, long)]
        test: Option<String>,

        /// Run in deterministic mode with fixed seed
        #[arg(long)]
        deterministic: bool,
    },

    /// Run benchmark suite against known protocols
    Benchmark {
        /// Benchmark dataset path
        #[arg(short, long, default_value = "./dataset")]
        dataset: PathBuf,

        /// Specific protocol to benchmark (e.g., axelar, dexalot, watt)
        #[arg(short, long)]
        protocol: Option<String>,

        /// Compare results against Trident Arena baseline
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        compare_baseline: bool,

        /// Generate benchmark report
        #[arg(short, long, default_value = "./ares-benchmark-report.json")]
        output: PathBuf,
    },

    /// Validate a proof-of-concept in sandboxed environment
    Validate {
        /// Path to PoC test or exploit script
        #[arg(value_name = "PATH")]
        poc_path: PathBuf,

        /// Fork mainnet state for realistic conditions
        #[arg(long)]
        fork_mainnet: bool,

        /// Specific slot to fork from
        #[arg(long)]
        fork_slot: Option<u64>,

        /// Override mainnet RPC URL for fork (e.g. Helius, QuickNode)
        #[arg(long)]
        rpc_url: Option<String>,
    },

    /// Fork-run every finding's PoC in a scan report and mark confirmed/refuted
    Confirm {
        /// Scan output directory (or a direct ares-report-*.json path)
        #[arg(value_name = "PATH")]
        scan_output: PathBuf,

        /// Fork mainnet state for realistic conditions
        #[arg(long)]
        fork_mainnet: bool,

        /// Specific slot to fork from
        #[arg(long)]
        fork_slot: Option<u64>,

        /// Override mainnet RPC URL for fork (e.g. Helius, QuickNode)
        #[arg(long)]
        rpc_url: Option<String>,
    },

    /// Report generation and export
    Report {
        /// Scan output directory to generate report from
        #[arg(value_name = "DIR")]
        scan_output: PathBuf,

        /// Report format
        #[arg(short, long, value_enum, default_value = "markdown")]
        format: ReportFormat,

        /// Output file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Check system dependencies and policy status
    Doctor {},

    /// Manage policy and capability escalation
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// Manage LLM configuration for the Agentic UI
    Llm {
        #[command(subcommand)]
        command: LlmCommands,
    },

    /// Generate self-contained HTML benchmark dashboard
    Dashboard {
        /// Path to benchmark JSON output
        #[arg(value_name = "FILE")]
        benchmark_json: PathBuf,

        /// Output file path
        #[arg(short, long, default_value = "./ares-dashboard.html")]
        output: PathBuf,

        /// Output format (html or pdf)
        #[arg(short, long, value_enum, default_value = "html")]
        format: ReportFormat,
    },
}

#[derive(Subcommand, Debug)]
enum LlmCommands {
    /// Configure API key and model (interactive or via flags)
    Setup {
        /// Provider (openai, anthropic, ollama)
        #[arg(short, long)]
        provider: Option<String>,
        /// API Key
        #[arg(short, long)]
        api_key: Option<String>,
        /// Model name (e.g. gpt-4o, claude-3-5-sonnet)
        #[arg(short, long)]
        model: Option<String>,
        /// Base URL (for Ollama or proxy)
        #[arg(short, long)]
        endpoint: Option<String>,
    },
    /// Show current LLM configuration
    Status,
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Show current policy status
    Status,
    /// Request capability escalation
    Escalate { capability: String },
    /// Reset policy to default
    Reset,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = match cli.verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };

    let is_tui = matches!(cli.command, Some(Commands::Interact {}) | None);

    let _log_guard = if is_tui {
        let file_appender = tracing_appender::rolling::never(".", "ares.log");
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        tracing_subscriber::fmt()
            .with_env_filter(format!("ares={}", log_level))
            .with_writer(non_blocking)
            .init();
        Some(guard)
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(format!("ares={}", log_level))
            .init();
        None
    };

    if !is_tui {
        info!("ARES V3 - Autonomous Solana Security Auditor");
        info!("Phase 1: Trident Integration + Multi-Agent Pipeline");
    }

    // Load or initialize config
    let config = if cli.config.exists() {
        load_config(&cli.config)?
    } else {
        warn!("Config file not found at {:?}, using defaults", cli.config);
        AresConfig::default()
    };

    // Route commands
    match cli.command {
        Some(Commands::Interact {}) | None => {
            info!("Starting ARES Agentic TUI");
            ares_v3::tui::run_tui(&config).await?;
        }
        Some(Commands::Init { path }) => {
            info!("Initializing ARES workspace at {:?}", path);
            ares_v3::commands::init::execute(&path).await?;
        }
        Some(Commands::Scan {
            program_path,
            target,
            full_pipeline,
            fuzz,
            poc,
            ast_scan,
            max_duration,
            output,
        }) => {
            info!(
                "Scanning {:?} | pipeline={} fuzz={} poc={} ast_scan={} duration={}s",
                program_path, full_pipeline, fuzz, poc, ast_scan, max_duration
            );
            ares_v3::commands::scan::execute(
                &program_path,
                &config,
                target,
                full_pipeline,
                fuzz,
                poc,
                ast_scan,
                max_duration,
                &output,
            )
            .await?;
        }
        Some(Commands::Fuzz {
            path,
            iterations,
            test,
            deterministic,
        }) => {
            info!(
                "Running fuzz campaign on {:?} | iterations={} deterministic={}",
                path, iterations, deterministic
            );
            ares_v3::commands::fuzz::execute(&path, iterations, test, deterministic).await?;
        }
        Some(Commands::Benchmark {
            dataset,
            protocol,
            compare_baseline,
            output,
        }) => {
            info!(
                "Running benchmark | dataset={:?} protocol={:?} compare={}",
                dataset, protocol, compare_baseline
            );
            ares_v3::commands::benchmark::execute(&dataset, protocol, compare_baseline, &output)
                .await?;
        }
        Some(Commands::Validate {
            poc_path,
            fork_mainnet,
            fork_slot,
            rpc_url,
        }) => {
            info!(
                "Validating PoC {:?} | fork_mainnet={} slot={:?} rpc={:?}",
                poc_path, fork_mainnet, fork_slot, rpc_url
            );
            ares_v3::commands::validate::execute(
                &poc_path,
                fork_mainnet,
                fork_slot,
                &config,
                rpc_url,
            )
            .await?;
        }
        Some(Commands::Confirm {
            scan_output,
            fork_mainnet,
            fork_slot,
            rpc_url,
        }) => {
            info!(
                "Confirming findings in {:?} | fork_mainnet={} slot={:?} rpc={:?}",
                scan_output, fork_mainnet, fork_slot, rpc_url
            );
            ares_v3::commands::confirm::execute(
                &scan_output,
                fork_mainnet,
                fork_slot,
                &config,
                rpc_url,
            )
            .await?;
        }
        Some(Commands::Report {
            scan_output,
            format,
            output,
        }) => {
            info!(
                "Generating report from {:?} | format={:?}",
                scan_output, format
            );
            ares_v3::commands::report::execute(&scan_output, format, output).await?;
        }
        Some(Commands::Doctor {}) => {
            ares_v3::commands::doctor::execute().await?;
        }
        Some(Commands::Policy { command }) => match command {
            PolicyCommands::Status => {
                ares_v3::commands::policy::status().await?;
            }
            PolicyCommands::Escalate { capability } => {
                ares_v3::commands::policy::escalate(&capability).await?;
            }
            PolicyCommands::Reset => {
                ares_v3::commands::policy::reset().await?;
            }
        },
        Some(Commands::Dashboard {
            benchmark_json,
            output,
            format,
        }) => {
            info!(
                "Generating dashboard from {:?} -> {:?} (format: {:?})",
                benchmark_json, output, format
            );
            ares_v3::commands::dashboard::execute(&benchmark_json, &output, format).await?;
        }
        Some(Commands::Llm { command }) => match command {
            LlmCommands::Setup {
                provider,
                api_key,
                model,
                endpoint,
            } => {
                ares_v3::commands::llm::setup(provider, api_key, model, endpoint, &cli.config)
                    .await?;
            }
            LlmCommands::Status => {
                ares_v3::commands::llm::status(&config).await?;
            }
        },
    }

    info!("ARES command completed successfully.");
    Ok(())
}

fn load_config(path: &PathBuf) -> Result<AresConfig> {
    let content = std::fs::read_to_string(path)?;
    let config: AresConfig = toml::from_str(&content)?;
    Ok(config)
}
