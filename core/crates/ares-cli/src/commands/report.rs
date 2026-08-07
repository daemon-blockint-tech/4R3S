use ares_core::AresResult;
use std::path::{Path, PathBuf};
use tracing::{error, info};

/// Generate report from scan output.
pub async fn execute(
    scan_output: &Path,
    format: crate::ReportFormat,
    output: Option<PathBuf>,
) -> AresResult<()> {
    info!("ARES Report Generation");
    info!("Input: {:?} | Format: {:?}", scan_output, format);

    // Read scan results (JSON)
    let output_path = output.clone();

    info!("Looking for scan results in: {:?}", scan_output);

    let mut found = false;
    let mut entries = tokio::fs::read_dir(scan_output).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("ares-report-") && name_str.ends_with(".json") {
            let content = tokio::fs::read_to_string(entry.path()).await?;
            let report: ares_core::AuditReport = serde_json::from_str(&content).map_err(|e| {
                ares_core::AresError::Parse(format!("Failed to parse report: {}", e))
            })?;

            found = true;
            info!("Loaded report for target: {}", report.target.name);

            match format {
                crate::ReportFormat::Json => {
                    let out = output_path
                        .as_ref()
                        .unwrap_or(&scan_output.join(format!("{}-report.json", report.target.name)))
                        .clone();
                    tokio::fs::write(&out, content).await?;
                    info!("JSON report written to: {:?}", out);
                }
                crate::ReportFormat::Markdown => {
                    let md = generate_markdown_report(&report);
                    let out = output_path
                        .as_ref()
                        .unwrap_or(&scan_output.join(format!("{}-report.md", report.target.name)))
                        .clone();
                    tokio::fs::write(&out, md).await?;
                    info!("Markdown report written to: {:?}", out);
                }
                crate::ReportFormat::Html => {
                    let html = generate_html_report(&report);
                    let out = output_path
                        .as_ref()
                        .unwrap_or(&scan_output.join(format!("{}-report.html", report.target.name)))
                        .clone();
                    tokio::fs::write(&out, html).await?;
                    info!("HTML report written to: {:?}", out);
                }
                crate::ReportFormat::Pdf => {
                    let out = output_path
                        .as_ref()
                        .unwrap_or(&scan_output.join(format!("{}-report.pdf", report.target.name)))
                        .clone();
                    crate::commands::pdf::generate_scan_pdf(&report, &out).map_err(|e| {
                        ares_core::AresError::Execution(format!("PDF generation failed: {}", e))
                    })?;
                    info!("PDF report written to: {:?}", out);
                }
                crate::ReportFormat::GithubIssue => {
                    let issue = generate_github_issue(&report);
                    let out = output_path
                        .as_ref()
                        .unwrap_or(
                            &scan_output.join(format!("{}-github-issue.md", report.target.name)),
                        )
                        .clone();
                    tokio::fs::write(&out, issue).await?;
                    info!("GitHub issue template written to: {:?}", out);
                }
            }
        }
    }

    if !found {
        error!("No ares-report-*.json files found in {:?}", scan_output);
        return Err(ares_core::AresError::NotFound(
            "No scan results found".to_string(),
        ));
    }

    Ok(())
}

fn generate_markdown_report(report: &ares_core::AuditReport) -> String {
    let mut md = "# ARES V3 Security Audit Report\n\n".to_string();
    md.push_str(&format!("**Target:** `{}`\n\n", report.target.name));
    md.push_str(&format!("**Date:** {}\n\n", report.metadata.generated_at));
    md.push_str(&format!(
        "**ARES Version:** {}\n\n",
        report.metadata.ares_version
    ));
    md.push_str(&format!(
        "**Duration:** {} seconds\n\n",
        report.metadata.scan_duration_secs
    ));
    md.push_str(&format!(
        "**Pipeline:** {}\n\n",
        report.metadata.agent_pipeline.join(" -> ")
    ));

    md.push_str("## Summary\n\n");
    md.push_str("| Severity | Count |\n");
    md.push_str("|----------|-------|\n");
    md.push_str(&format!(
        "| Critical | {} |\n",
        report.summary.critical_count
    ));
    md.push_str(&format!("| High     | {} |\n", report.summary.high_count));
    md.push_str(&format!("| Medium   | {} |\n", report.summary.medium_count));
    md.push_str(&format!("| Low      | {} |\n", report.summary.low_count));
    md.push_str(&format!(
        "| Info     | {} |\n\n",
        report.summary.informational_count
    ));

    // Phase 4: Economic impact summary
    let total_sol = report.summary.total_economic_impact_lamports as f64 / 1_000_000_000.0;
    let max_sol = report.summary.max_single_exploit_lamports as f64 / 1_000_000_000.0;
    md.push_str("## Economic Impact Estimate\n\n");
    md.push_str("| Metric | Value |\n");
    md.push_str("|--------|-------|\n");
    md.push_str(&format!(
        "| Total Extractable Value | {:.4} SOL |\n",
        total_sol
    ));
    md.push_str(&format!("| Max Single Exploit | {:.4} SOL |\n\n", max_sol));

    md.push_str("## Findings\n\n");

    for (i, finding) in report.findings.iter().enumerate() {
        md.push_str(&format!(
            "### {}. {} [{}]\n\n",
            i + 1,
            finding.title,
            finding.severity
        ));
        md.push_str(&format!("**ID:** `{}`\n\n", finding.id));
        md.push_str(&format!("**Category:** {}\n\n", finding.category));
        md.push_str(&format!(
            "**Confidence:** {:.0}%\n\n",
            finding.confidence * 100.0
        ));
        let exploit_lamports = crate::scorer::ExploitScorer::score_finding(finding);
        let exploit_sol = exploit_lamports as f64 / 1_000_000_000.0;
        md.push_str(&format!(
            "**Estimated Extractable Value:** {:.4} SOL\n\n",
            exploit_sol
        ));
        md.push_str(&format!("**Description:**\n{}\n\n", finding.description));

        if let Some(ref poc) = finding.proof_of_concept {
            md.push_str(&format!("**Proof of Concept:** `{:?}`\n\n", poc));
        }

        md.push_str(&format!(
            "**Recommendation:**\n{}\n\n",
            finding.recommendation
        ));

        if !finding.references.is_empty() {
            md.push_str("**References:**\n");
            for r in &finding.references {
                md.push_str(&format!("- {}\n", r));
            }
            md.push('\n');
        }

        md.push_str("---\n\n");
    }

    md.push_str("## Tools Used\n\n");
    for tool in &report.metadata.tools_used {
        md.push_str(&format!("- {}\n", tool));
    }
    md.push('\n');

    md.push_str("---\n\n*Generated by ARES V3 — Autonomous Solana Security Auditor*\n");

    md
}

/// Render the HTML report.
///
/// Delegates to `ares_report::generate_html`, which HTML-escapes the markdown
/// before applying its markdown→HTML substitutions. This function used to carry
/// its own copy of that substitution chain with the escaping step missing, so the
/// hardening in `ares-report` protected nobody: `report --format html` called the
/// unescaped copy. `target.name` comes from the audited directory's own name, so
/// unpacking a program into a directory called
/// `x"><img src=x onerror=...>` put attacker script into the `<title>` and body
/// of the artifact handed to the client. One renderer, escaped, is the fix —
/// keeping two was what let them drift apart unnoticed.
fn generate_html_report(report: &ares_core::AuditReport) -> String {
    ares_report::generate_html(report)
}

fn generate_github_issue(report: &ares_core::AuditReport) -> String {
    let mut issue = format!(
        "## Security Audit Findings for `{}`\n\n",
        report.target.name
    );

    issue.push_str("### Summary\n\n");
    issue.push_str(&format!(
        "- **Critical:** {}\n",
        report.summary.critical_count
    ));
    issue.push_str(&format!("- **High:** {}\n", report.summary.high_count));
    issue.push_str(&format!("- **Medium:** {}\n", report.summary.medium_count));
    issue.push_str(&format!("- **Low:** {}\n\n", report.summary.low_count));

    issue.push_str("### Findings\n\n");

    for finding in &report.findings {
        issue.push_str(&format!("#### `{}` — {}\n\n", finding.id, finding.title));
        issue.push_str(&format!("- **Severity:** {}\n", finding.severity));
        issue.push_str(&format!("- **Category:** {}\n", finding.category));
        issue.push_str(&format!(
            "- **Confidence:** {:.0}%\n",
            finding.confidence * 100.0
        ));
        issue.push_str(&format!("\n{}", finding.description));
        issue.push_str(&format!(
            "\n\n**Recommendation:** {}\n\n",
            finding.recommendation
        ));
        if let Some(ref poc) = finding.proof_of_concept {
            issue.push_str(&format!("**PoC:** `{:?}`\n\n", poc));
        }
        issue.push_str("---\n\n");
    }

    issue.push_str("### Environment\n\n");
    issue.push_str(&format!(
        "- **ARES Version:** {}\n",
        report.metadata.ares_version
    ));
    issue.push_str(&format!(
        "- **Scan Date:** {}\n",
        report.metadata.generated_at
    ));
    issue.push_str(&format!(
        "- **Pipeline:** {}\n",
        report.metadata.agent_pipeline.join(", ")
    ));
    issue.push_str(&format!(
        "- **Tools:** {}\n",
        report.metadata.tools_used.join(", ")
    ));
    issue.push_str("\n---\n\n*Reported by ARES V3 Autonomous Security Auditor*\n");

    issue
}
