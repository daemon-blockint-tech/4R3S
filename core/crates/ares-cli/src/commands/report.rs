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

fn generate_html_report(report: &ares_core::AuditReport) -> String {
    // Phase 1: simple HTML wrapper around markdown content (no external markdown-to-html dep)
    let md = generate_markdown_report(report);
    // Very basic markdown-to-html conversion for Phase 1
    let html_body = md
        .replace("# ", "<h1>")
        .replace("\n## ", "</p><h2>")
        .replace("\n### ", "</p><h3>")
        .replace("\n\n", "</p><p>")
        .replace("```", "<pre><code>")
        .replace("`", "<code>")
        .replace("| ", "<td>")
        .replace(" |", "</td>")
        .replace("---\n", "</tr><tr>")
        .replace("**", "<strong>")
        .replace("- ", "<li>")
        .replace("\n</p>", "</p>");

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>ARES V3 Audit Report - {}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #333; }}
        h1 {{ color: #1a1a1a; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
        h2 {{ color: #2c3e50; margin-top: 30px; }}
        h3 {{ color: #e74c3c; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #f5f5f5; font-weight: 600; }}
        tr:nth-child(even) {{ background-color: #fafafa; }}
        .critical {{ color: #c0392b; font-weight: bold; }}
        .high {{ color: #e67e22; font-weight: bold; }}
        .medium {{ color: #f39c12; font-weight: bold; }}
        code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'SF Mono', Monaco, monospace; font-size: 0.9em; }}
        hr {{ border: none; border-top: 1px solid #eee; margin: 30px 0; }}
        pre {{ background: #f8f8f8; padding: 16px; border-radius: 4px; overflow-x: auto; }}
        p {{ margin: 0 0 16px 0; }}
    </style>
</head>
<body>
<div class="report">
{}
</div>
</body>
</html>"#,
        report.target.name, html_body
    )
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
