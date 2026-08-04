use ares_core::AresResult;
use printpdf::*;
use serde_json::Value;
use std::fs::File;
use std::io::BufWriter;
use std::path::Path;
use tracing::info;

/// Generate a PDF benchmark report from the JSON output of `ares benchmark`.
/// Pure Rust — no external binaries (wkhtmltopdf, pandoc, Edge, etc.).
/// Cross-platform and deployment-safe.
pub async fn generate_benchmark_pdf(benchmark_json: &Path, output: &Path) -> AresResult<()> {
    info!("ARES Benchmark PDF Generation");
    info!("Input: {:?} | Output: {:?}", benchmark_json, output);

    if !benchmark_json.exists() {
        return Err(ares_core::AresError::NotFound(format!(
            "Benchmark JSON not found: {:?}",
            benchmark_json
        )));
    }

    let content = tokio::fs::read_to_string(benchmark_json).await?;
    let json: Value = serde_json::from_str(&content)
        .map_err(|e| ares_core::AresError::Parse(format!("Invalid benchmark JSON: {}", e)))?;

    let output_path = output.to_path_buf();
    tokio::task::spawn_blocking(move || build_pdf(&json, &output_path))
        .await
        .map_err(|e| {
            ares_core::AresError::Execution(format!("PDF generation panicked: {}", e))
        })??;

    info!("PDF report written to: {:?}", output);
    Ok(())
}

fn build_pdf(json: &Value, output: &Path) -> AresResult<()> {
    let (doc, page, layer) =
        PdfDocument::new("ARES V3 Benchmark Report", Mm(210.0), Mm(297.0), "Layer 1");
    let current_layer = doc.get_page(page).get_layer(layer);
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| ares_core::AresError::Execution(format!("Font error: {:?}", e)))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| ares_core::AresError::Execution(format!("Font error: {:?}", e)))?;

    let mut y = Mm(280.0);
    let left = Mm(15.0);
    let _line = Mm(5.0);

    fn write_line(
        layer: &PdfLayerReference,
        text: &str,
        x: Mm,
        y: &mut Mm,
        font: &IndirectFontRef,
        size: f32,
    ) {
        layer.use_text(text, size, x, *y, font);
        *y = Mm(y.0 - size * 0.4);
    }

    // Title
    write_line(
        &current_layer,
        "ARES V3 Benchmark Report",
        left,
        &mut y,
        &font_bold,
        18.0,
    );
    write_line(
        &current_layer,
        "Ground-truth benchmark vs Trident Arena",
        left,
        &mut y,
        &font,
        10.0,
    );
    y = Mm(y.0 - 5.0);

    // Summary
    let summary = json.get("summary").cloned().unwrap_or_default();
    let total_tested = summary
        .get("total_tested")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let total_detections = summary
        .get("total_detections")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let avg_rate = summary
        .get("avg_detection_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let total_economic = summary
        .get("total_economic_score_lamports")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
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

    write_line(&current_layer, "Summary", left, &mut y, &font_bold, 14.0);
    write_line(
        &current_layer,
        &format!("Protocols Tested: {}", total_tested),
        left,
        &mut y,
        &font,
        10.0,
    );
    write_line(
        &current_layer,
        &format!("Total Detections: {}", total_detections),
        left,
        &mut y,
        &font,
        10.0,
    );
    write_line(
        &current_layer,
        &format!("Avg Detection Rate: {:.1}%", avg_rate * 100.0),
        left,
        &mut y,
        &font,
        10.0,
    );
    write_line(
        &current_layer,
        &format!(
            "Total Economic Impact: {:.4} SOL",
            total_economic as f64 / 1_000_000_000.0
        ),
        left,
        &mut y,
        &font,
        10.0,
    );
    write_line(
        &current_layer,
        &format!(
            "Precision: {:.2} | Recall: {:.2} | F1: {:.2}",
            avg_precision, avg_recall, avg_f1
        ),
        left,
        &mut y,
        &font,
        10.0,
    );
    y = Mm(y.0 - 5.0);

    let results = json
        .get("results")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    // Segment A
    write_line(
        &current_layer,
        "Segment A: Stub Regression Suite (Deterministic Pattern Validation)",
        left,
        &mut y,
        &font_bold,
        12.0,
    );
    write_line(
        &current_layer,
        "100-150 LOC reproduction stubs. 100% detection is the design goal — regression suite.",
        left,
        &mut y,
        &font,
        9.0,
    );
    y = Mm(y.0 - 2.0);

    let stubs = [
        "ownership-check",
        "arbitrary-cpi",
        "initialization-frontrunning",
        "re-initialization",
        "account-reloading",
        "revival-attack",
        "duplicate-mutable-accounts",
        "type-cosplay",
        "missing-revalidation",
        "reentrancy-risk",
        "unchecked-cast",
    ];
    for r in &results {
        let name = r
            .get("protocol_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if !stubs.contains(&name) {
            continue;
        }
        let detected = r
            .get("detected_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let total = r
            .get("total_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .max(1) as usize;
        let rate = (detected as f64 / total as f64) * 100.0;
        write_line(
            &current_layer,
            &format!("  {} — {}/{} ({:.0}%)", name, detected, total, rate),
            left,
            &mut y,
            &font,
            10.0,
        );
    }
    y = Mm(y.0 - 5.0);

    // Segment B
    write_line(
        &current_layer,
        "Segment B: Real-World Capability Assessment (Production 10K+ LOC Repos)",
        left,
        &mut y,
        &font_bold,
        12.0,
    );
    write_line(&current_layer, "Honest underperformance (<100%, >0% FP) expected with Phase-1 regex/heuristics on macro-heavy code.", left, &mut y, &font, 9.0);
    y = Mm(y.0 - 2.0);

    let real_protocols = [
        "axelar",
        "dexalot",
        "bert-staking",
        "pump-science",
        "metadao",
    ];
    for r in &results {
        let name = r
            .get("protocol_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        if !real_protocols.contains(&name) {
            continue;
        }
        let detected = r
            .get("detected_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let total = r
            .get("total_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .max(1) as usize;
        let rate = (detected as f64 / total as f64) * 100.0;
        let precision = r.get("precision").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let recall = r.get("recall").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let f1 = r.get("f1_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let time = r
            .get("execution_time_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        write_line(
            &current_layer,
            &format!(
                "  {} — {}/{} ({:.0}%) | P:{:.2} R:{:.2} F1:{:.2} | {}s",
                name, detected, total, rate, precision, recall, f1, time
            ),
            left,
            &mut y,
            &font,
            10.0,
        );
    }
    y = Mm(y.0 - 5.0);

    // All protocols
    write_line(
        &current_layer,
        "Per-Protocol Results (All Protocols)",
        left,
        &mut y,
        &font_bold,
        12.0,
    );
    for r in &results {
        let name = r
            .get("protocol_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let detected = r
            .get("detected_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;
        let total = r
            .get("total_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(1)
            .max(1) as usize;
        let rate = (detected as f64 / total as f64) * 100.0;
        let precision = r.get("precision").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let recall = r.get("recall").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let f1 = r.get("f1_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let time = r
            .get("execution_time_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        write_line(
            &current_layer,
            &format!(
                "  {} — {}/{} ({:.1}%) P:{:.2} R:{:.2} F1:{:.2} {}s",
                name, detected, total, rate, precision, recall, f1, time
            ),
            left,
            &mut y,
            &font,
            10.0,
        );
    }
    y = Mm(y.0 - 5.0);

    // Footer
    write_line(
        &current_layer,
        "Generated by ARES V3 — Autonomous Solana Security Auditor",
        left,
        &mut y,
        &font,
        9.0,
    );
    write_line(
        &current_layer,
        "Pure-Rust PDF generation (printpdf) — no external browser or binary dependencies.",
        left,
        &mut y,
        &font,
        9.0,
    );

    let file = File::create(output).map_err(ares_core::AresError::Io)?;
    doc.save(&mut BufWriter::new(file))
        .map_err(|e| ares_core::AresError::Execution(format!("Failed to write PDF: {:?}", e)))?;

    Ok(())
}

/// Generate a simple PDF audit report from an `AuditReport`.
/// Pure Rust — no external binaries.
pub fn generate_scan_pdf(report: &ares_core::AuditReport, output: &Path) -> AresResult<()> {
    let (doc, page, layer) = PdfDocument::new(
        format!("ARES Audit Report — {}", report.target.name),
        Mm(210.0),
        Mm(297.0),
        "Layer 1",
    );
    let current_layer = doc.get_page(page).get_layer(layer);
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| ares_core::AresError::Execution(format!("Font error: {:?}", e)))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| ares_core::AresError::Execution(format!("Font error: {:?}", e)))?;

    let mut y = Mm(280.0);
    let left = Mm(15.0);

    fn line(
        layer: &PdfLayerReference,
        text: &str,
        x: Mm,
        y: &mut Mm,
        font: &IndirectFontRef,
        size: f32,
    ) {
        layer.use_text(text, size, x, *y, font);
        *y = Mm(y.0 - size * 0.4);
    }

    line(
        &current_layer,
        &format!("ARES V3 Security Audit Report — {}", report.target.name),
        left,
        &mut y,
        &font_bold,
        16.0,
    );
    line(
        &current_layer,
        &format!(
            "Date: {} | Version: {} | Duration: {}s",
            report.metadata.generated_at,
            report.metadata.ares_version,
            report.metadata.scan_duration_secs
        ),
        left,
        &mut y,
        &font,
        10.0,
    );
    y = Mm(y.0 - 5.0);

    line(&current_layer, "Summary", left, &mut y, &font_bold, 14.0);
    line(
        &current_layer,
        &format!(
            "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
            report.summary.critical_count,
            report.summary.high_count,
            report.summary.medium_count,
            report.summary.low_count,
            report.summary.informational_count
        ),
        left,
        &mut y,
        &font,
        10.0,
    );
    y = Mm(y.0 - 5.0);

    line(&current_layer, "Findings", left, &mut y, &font_bold, 14.0);
    for (i, finding) in report.findings.iter().enumerate() {
        line(
            &current_layer,
            &format!("{}. {} [{}]", i + 1, finding.title, finding.severity),
            left,
            &mut y,
            &font_bold,
            11.0,
        );
        line(
            &current_layer,
            &format!(
                "   Category: {} | Confidence: {:.0}%",
                finding.category,
                finding.confidence * 100.0
            ),
            left,
            &mut y,
            &font,
            10.0,
        );
        line(
            &current_layer,
            &format!("   {}", finding.description.replace('\n', " ")),
            left,
            &mut y,
            &font,
            9.0,
        );
        line(
            &current_layer,
            &format!(
                "   Recommendation: {}",
                finding.recommendation.replace('\n', " ")
            ),
            left,
            &mut y,
            &font,
            9.0,
        );
        y = Mm(y.0 - 2.0);
    }

    y = Mm(y.0 - 3.0);
    line(
        &current_layer,
        "Generated by ARES V3 — Autonomous Solana Security Auditor",
        left,
        &mut y,
        &font,
        9.0,
    );
    line(
        &current_layer,
        "Pure-Rust PDF generation (printpdf) — no external browser or binary dependencies.",
        left,
        &mut y,
        &font,
        9.0,
    );

    let file = File::create(output).map_err(ares_core::AresError::Io)?;
    doc.save(&mut BufWriter::new(file))
        .map_err(|e| ares_core::AresError::Execution(format!("Failed to write PDF: {:?}", e)))?;

    Ok(())
}
