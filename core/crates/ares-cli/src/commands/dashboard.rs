use ares_core::AresResult;
use serde_json::Value;
use std::path::Path;
use tracing::info;

/// Generate a self-contained HTML benchmark comparison dashboard.
/// Reads the JSON output from `ares benchmark` and produces an HTML file
/// with inline CSS/SVG visualizations — no external dependencies.
pub async fn execute(
    benchmark_json: &Path,
    output: &Path,
    format: crate::ReportFormat,
) -> AresResult<()> {
    info!("ARES Benchmark Dashboard");
    info!(
        "Input: {:?} | Output: {:?} | Format: {:?}",
        benchmark_json, output, format
    );

    if !benchmark_json.exists() {
        return Err(ares_core::AresError::NotFound(format!(
            "Benchmark JSON not found: {:?}",
            benchmark_json
        )));
    }

    match format {
        crate::ReportFormat::Pdf => {
            crate::commands::pdf::generate_benchmark_pdf(benchmark_json, output).await?;
        }
        _ => {
            // Default to HTML for any non-Pdf variant (including Html, Markdown, Json, GithubIssue)
            let content = tokio::fs::read_to_string(benchmark_json).await?;
            let json: Value = serde_json::from_str(&content).map_err(|e| {
                ares_core::AresError::Parse(format!("Invalid benchmark JSON: {}", e))
            })?;
            let html = generate_dashboard_html(&json);
            tokio::fs::write(output, html).await?;
            info!("Dashboard written to: {:?}", output);
        }
    }

    Ok(())
}

fn generate_dashboard_html(json: &Value) -> String {
    let results = json
        .get("results")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    let summary = json.get("summary").cloned().unwrap_or_default();

    let total_tested = summary
        .get("total_tested")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    // Key names mirror the benchmark summary written by benchmark/execute.rs.
    let total_detections = summary
        .get("total_known_audit_findings_detected")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let avg_rate = summary
        .get("avg_known_audit_recall")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let total_economic = summary
        .get("total_economic_score_lamports")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let baseline_rate = summary
        .get("baseline_trident_arena")
        .and_then(|b| b.get("detection_rate"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.70);

    // Phase 6: Precision/Recall/F1 from ground truth
    let avg_precision = summary
        .get("avg_precision")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let avg_recall = summary
        .get("avg_recall")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let avg_f1 = summary
        .get("avg_f1_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    let protocol_rows: String = results
        .iter()
        .map(|r| {
            let name = r
                .get("protocol_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let detected = r
                .get("detected_critical_high")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total = r
                .get("total_critical_high")
                .and_then(|v| v.as_u64())
                .unwrap_or(1)
                .max(1);
            let rate = r
                .get("detection_rate")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let economic = r
                .get("economic_score_lamports")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let time = r
                .get("execution_time_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let precision = r.get("precision").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let recall = r.get("recall").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let f1 = r.get("f1_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let rate_pct = rate * 100.0;
            let bar_width = rate_pct.min(100.0);
            let color = if rate >= 0.83 {
                "#27ae60"
            } else if rate >= 0.50 {
                "#f39c12"
            } else {
                "#e74c3c"
            };
            format!(
                r#"<tr>
                    <td>{}</td>
                    <td>{}/{}</td>
                    <td>
                        <div class="bar-container">
                            <div class="bar" style="width: {:.1}%; background: {};"></div>
                        </div>
                        <span class="bar-label">{:.1}%</span>
                    </td>
                    <td>{:.2}</td>
                    <td>{:.2}</td>
                    <td>{:.2}</td>
                    <td>{:.4} SOL</td>
                    <td>{}s</td>
                </tr>"#,
                name,
                detected,
                total,
                bar_width,
                color,
                rate_pct,
                precision,
                recall,
                f1,
                economic as f64 / 1_000_000_000.0,
                time
            )
        })
        .collect();

    // Trident Arena head-to-head rows (6 benchmark protocols)
    // Expected totals match Trident Arena's published retrospective benchmark counts.
    let trident_expected_totals: std::collections::HashMap<&str, usize> = [
        ("axelar", 7),
        ("bert-staking", 2),
        ("dexalot", 5),
        ("pump-science", 2),
        ("metadao", 3),
        ("watt", 11),
    ]
    .iter()
    .copied()
    .collect();

    let trident_baseline_detected: std::collections::HashMap<&str, usize> = [
        ("axelar", 5),
        ("bert-staking", 1),
        ("dexalot", 4),
        ("pump-science", 1),
        ("metadao", 3),
        ("watt", 7),
    ]
    .iter()
    .copied()
    .collect();

    let mut trident_rows_vec = Vec::new();
    let mut ares_trident_total_tp = 0usize;
    let mut ares_trident_total_expected = 0usize;
    for r in &results {
        let name = r
            .get("protocol_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(&expected_total) = trident_expected_totals.get(name) {
            let ares_detected = (r
                .get("detected_critical_high")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize)
                .min(expected_total); // cap at expected findings count
            let trident_detected = trident_baseline_detected.get(name).copied().unwrap_or(0);
            let ares_rate = (ares_detected as f64 / expected_total as f64) * 100.0;
            let trident_rate = (trident_detected as f64 / expected_total as f64) * 100.0;
            ares_trident_total_tp += ares_detected;
            ares_trident_total_expected += expected_total;
            trident_rows_vec.push(format!(
                r#"<tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td><strong>{}/{} ({:.0}%)</strong></td>
                    <td>{}/{} ({:.0}%)</td>
                </tr>"#,
                name,
                expected_total,
                ares_detected,
                expected_total,
                ares_rate,
                trident_detected,
                expected_total,
                trident_rate
            ));
        }
    }
    let ares_trident_total_rate = if ares_trident_total_expected > 0 {
        (ares_trident_total_tp as f64 / ares_trident_total_expected as f64) * 100.0
    } else {
        0.0
    };
    trident_rows_vec.push(format!(
        r#"<tr style="font-weight:700;background:rgba(56,189,248,0.08);">
            <td>TOTAL</td>
            <td>{}</td>
            <td><strong>{}/{} ({:.0}%)</strong></td>
            <td>21/30 (70%)</td>
        </tr>"#,
        ares_trident_total_expected,
        ares_trident_total_tp,
        ares_trident_total_expected,
        ares_trident_total_rate
    ));
    let trident_rows = trident_rows_vec.join("\n");

    // Extended benchmark rows (protocols tested by ARES V3 but NOT in Trident Arena's 6)
    let mut ext_rows_vec = Vec::new();
    let mut ext_total_tp = 0usize;
    let mut ext_total_expected = 0usize;
    for r in &results {
        let name = r
            .get("protocol_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if trident_expected_totals.contains_key(name) {
            continue;
        }
        let expected = r
            .get("total_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .max(1) as usize;
        let detected = (r
            .get("detected_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize)
            .min(expected);
        ext_total_tp += detected;
        ext_total_expected += expected;
        let rate = (detected as f64 / expected as f64) * 100.0;
        ext_rows_vec.push(format!(
            r#"<tr>
                <td>{}</td>
                <td>{}</td>
                <td><strong>{}/{} ({:.0}%)</strong></td>
                <td>—</td>
            </tr>"#,
            name, expected, detected, expected, rate
        ));
    }
    let ext_total_rate = if ext_total_expected > 0 {
        (ext_total_tp as f64 / ext_total_expected as f64) * 100.0
    } else {
        0.0
    };
    ext_rows_vec.push(format!(
        r#"<tr style="font-weight:700;background:rgba(56,189,248,0.08);">
            <td>TOTAL</td>
            <td>{}</td>
            <td><strong>{}/{} ({:.0}%)</strong></td>
            <td>—</td>
        </tr>"#,
        ext_total_expected, ext_total_tp, ext_total_expected, ext_total_rate
    ));
    let ext_rows = ext_rows_vec.join("\n");

    // Overall comparison bar (ARES vs Trident Arena baseline)
    let ares_bar_width = (avg_rate * 100.0).min(100.0);
    let baseline_bar_width = (baseline_rate * 100.0).min(100.0);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ARES V3 Benchmark Dashboard</title>
<style>
:root {{
    --bg: #0f1117;
    --surface: #1a1d26;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --critical: #ef4444;
    --success: #22c55e;
    --warning: #f59e0b;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 40px 20px;
}}
.container {{ max-width: 1100px; margin: 0 auto; }}
h1 {{ font-size: 2rem; margin-bottom: 8px; }}
.subtitle {{ color: var(--muted); margin-bottom: 32px; }}
.kpis {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
}}
.kpi {{
    background: var(--surface);
    border-radius: 12px;
    padding: 20px;
    border: 1px solid rgba(255,255,255,0.05);
}}
.kpi-value {{ font-size: 2rem; font-weight: 700; color: var(--accent); }}
.kpi-label {{ font-size: 0.875rem; color: var(--muted); margin-top: 4px; }}
.comparison {{
    background: var(--surface);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 32px;
    border: 1px solid rgba(255,255,255,0.05);
}}
.comparison h2 {{ font-size: 1.25rem; margin-bottom: 16px; }}
.metrics-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 16px;
}}
.metric-box {{
    background: rgba(255,255,255,0.03);
    border-radius: 8px;
    padding: 16px;
}}
.metric-value {{ font-size: 1.5rem; font-weight: 700; color: var(--success); }}
.metric-label {{ font-size: 0.8rem; color: var(--muted); }}
.bar-group {{ margin-bottom: 16px; }}
.bar-group-label {{ display: flex; justify-content: space-between; font-size: 0.875rem; margin-bottom: 6px; }}
.bar-track {{
    height: 24px;
    background: rgba(255,255,255,0.08);
    border-radius: 6px;
    overflow: hidden;
    position: relative;
}}
.bar-fill {{
    height: 100%;
    border-radius: 6px;
    transition: width 0.6s ease;
    display: flex;
    align-items: center;
    padding-left: 8px;
    font-size: 0.75rem;
    font-weight: 600;
    color: #fff;
    text-shadow: 0 1px 2px rgba(0,0,0,0.4);
}}
.table-wrap {{
    background: var(--surface);
    border-radius: 12px;
    padding: 24px;
    border: 1px solid rgba(255,255,255,0.05);
    overflow-x: auto;
}}
table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
th {{ text-align: left; padding: 12px 8px; color: var(--muted); font-weight: 500; border-bottom: 1px solid rgba(255,255,255,0.08); }}
td {{ padding: 12px 8px; border-bottom: 1px solid rgba(255,255,255,0.04); }}
tr:hover td {{ background: rgba(255,255,255,0.02); }}
.bar-container {{
    width: 100%;
    height: 10px;
    background: rgba(255,255,255,0.08);
    border-radius: 5px;
    overflow: hidden;
    margin-bottom: 4px;
}}
.bar {{
    height: 100%;
    border-radius: 5px;
    transition: width 0.5s ease;
}}
.bar-label {{ font-size: 0.75rem; color: var(--muted); }}
.footer {{ margin-top: 32px; color: var(--muted); font-size: 0.875rem; text-align: center; }}
</style>
</head>
<body>
<div class="container">
    <h1>ARES V3 Benchmark Dashboard</h1>
    <p class="subtitle">Ground-truth benchmark vs Trident Arena on solana-common-attack-vectors dataset</p>

    <div class="kpis">
        <div class="kpi">
            <div class="kpi-value">{}</div>
            <div class="kpi-label">Protocols Tested</div>
        </div>
        <div class="kpi">
            <div class="kpi-value">{}</div>
            <div class="kpi-label">Total Detections</div>
        </div>
        <div class="kpi">
            <div class="kpi-value">{:.1}%</div>
            <div class="kpi-label">Avg Detection Rate</div>
        </div>
        <div class="kpi">
            <div class="kpi-value">{:.4} SOL</div>
            <div class="kpi-label">Total Economic Score</div>
        </div>
    </div>

    <div class="comparison">
        <h2>Detection Rate Comparison</h2>
        <div class="bar-group">
            <div class="bar-group-label">
                <span>ARES V3</span>
                <span>{:.1}%</span>
            </div>
            <div class="bar-track">
                <div class="bar-fill" style="width: {:.1}%; background: var(--accent);">
                    ARES
                </div>
            </div>
        </div>
        <div class="bar-group">
            <div class="bar-group-label">
                <span>Trident Arena (baseline)</span>
                <span>{:.1}%</span>
            </div>
            <div class="bar-track">
                <div class="bar-fill" style="width: {:.1}%; background: var(--muted);">
                    Trident
                </div>
            </div>
        </div>

        <h2 style="margin-top: 24px;">ARES V3 Precision / Recall / F1 (Ground Truth)</h2>
        <div class="metrics-grid">
            <div class="metric-box">
                <div class="metric-value">{:.2}</div>
                <div class="metric-label">Avg Precision</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{:.2}</div>
                <div class="metric-label">Avg Recall</div>
            </div>
            <div class="metric-box">
                <div class="metric-value">{:.2}</div>
                <div class="metric-label">Avg F1 Score</div>
            </div>
        </div>
    </div>

    <div class="table-wrap">
        <h2 style="margin-bottom: 16px;">Segment B: Real-World Capability Assessment (Production 10K+ LOC Repos)</h2>
        <p style="margin-bottom: 12px; font-size: 0.8rem; color: var(--muted);">
            These are real cloned production repositories scanned with coarse Phase-1 regex/heuristic static analysis. Honest underperformance (&lt;100% detection, &gt;0% FP) is expected because production code uses macros, safe wrappers, and refactored variable names that evade simple patterns. Trident Arena's published benchmark covers 6 protocols (Axelar, Bert Staking, Dexalot, Pump Science, MetaDAO, Watt).
        </p>
        <table>
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Critical/High Total</th>
                    <th>ARES V3</th>
                    <th>Trident Arena</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>

    <div class="table-wrap">
        <h2 style="margin-bottom: 16px;">Segment A: Stub Regression Suite (Deterministic Pattern Validation)</h2>
        <p style="margin-bottom: 12px; font-size: 0.8rem; color: var(--muted);">
            50–150 LOC reproduction stubs isolating single vulnerability classes. 100% detection is the design goal — this is a <strong>regression suite</strong>, not a claim of real-world superiority. Trident Arena did not evaluate these protocols.
        </p>
        <table>
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Critical/High Total</th>
                    <th>ARES V3</th>
                    <th>Trident Arena</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>

    <div class="table-wrap">
        <h2 style="margin-bottom: 16px;">Per-Protocol Results (All Protocols)</h2>
        <table>
            <thead>
                <tr>
                    <th>Protocol</th>
                    <th>Detected / Total</th>
                    <th>Detection Rate</th>
                    <th>Precision</th>
                    <th>Recall</th>
                    <th>F1</th>
                    <th>Economic Impact</th>
                    <th>Time</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>

    <div class="footer">
        Generated by ARES V3 — Autonomous Solana Security Auditor<br>
        Dashboard is fully self-contained (no external network requests)
    </div>
</div>
</body>
</html>"#,
        total_tested,
        total_detections,
        avg_rate * 100.0,
        total_economic as f64 / 1_000_000_000.0,
        avg_rate * 100.0,
        ares_bar_width,
        baseline_rate * 100.0,
        baseline_bar_width,
        avg_precision,
        avg_recall,
        avg_f1,
        trident_rows,
        ext_rows,
        protocol_rows
    )
}
