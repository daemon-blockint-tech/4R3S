pub mod commands;
pub mod fork_validator;
pub mod idl;
pub mod llm_judge;
pub mod poc;
pub mod scorer;
pub mod tui;
pub mod validator;

/// Re-export SDK crates for unified access
pub use ares_orchestrator as agent;
pub use ares_report;

/// Report format options for export.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ReportFormat {
    Markdown,
    Pdf,
    Json,
    Html,
    GithubIssue,
}
