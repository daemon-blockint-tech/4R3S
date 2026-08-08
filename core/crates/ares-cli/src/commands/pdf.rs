use ares_core::AresResult;
use printpdf::*;
use serde_json::Value;
use std::path::Path;
use tracing::info;

const PAGE_WIDTH: Mm = Mm(210.0);
const PAGE_HEIGHT: Mm = Mm(297.0);
/// Vertical cursor start, and the margin below which a line would fall off the page.
const CURSOR_TOP: f32 = 280.0;
const CURSOR_BOTTOM: f32 = 15.0;
const MARGIN_LEFT: Mm = Mm(15.0);

/// Sequential text writer over one or more A4 pages.
///
/// printpdf 0.12 replaced the 0.7 layer API (`PdfLayerReference::use_text`) with a
/// flat op list per page, so the text cursor is ours to track. That is also what
/// makes the page break here possible: the 0.7 code decremented `y` without a
/// lower bound, so any report taller than one page emitted its remaining lines at
/// a negative coordinate — off the media box, invisible in every reader. A scan
/// with more findings than fit on one page silently lost them, which is the worst
/// possible failure for an audit deliverable: the document still looks complete.
struct Canvas {
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    y: f32,
}

impl Canvas {
    fn new() -> Self {
        Self {
            pages: Vec::new(),
            ops: vec![Op::StartTextSection],
            y: CURSOR_TOP,
        }
    }

    /// Emit one line at the current cursor and advance down by the font size.
    fn line(&mut self, text: &str, size: f32, bold: bool) {
        if self.y < CURSOR_BOTTOM {
            self.end_page();
        }
        let font = PdfFontHandle::Builtin(if bold {
            BuiltinFont::HelveticaBold
        } else {
            BuiltinFont::Helvetica
        });
        self.ops.push(Op::SetFont {
            font,
            size: Pt(size),
        });
        self.ops.push(Op::SetTextCursor {
            pos: Point {
                x: MARGIN_LEFT.into(),
                y: Mm(self.y).into(),
            },
        });
        self.ops.push(Op::ShowText {
            items: vec![TextItem::Text(text.to_string())],
        });
        self.y -= size * 0.4;
    }

    /// Vertical whitespace, in mm. Never triggers a page break on its own — a gap
    /// that lands past the bottom is absorbed by the next `line`.
    fn gap(&mut self, mm: f32) {
        self.y -= mm;
    }

    fn end_page(&mut self) {
        let mut ops = std::mem::replace(&mut self.ops, vec![Op::StartTextSection]);
        ops.push(Op::EndTextSection);
        self.pages.push(PdfPage::new(PAGE_WIDTH, PAGE_HEIGHT, ops));
        self.y = CURSOR_TOP;
    }

    fn save(mut self, title: &str, output: &Path) -> AresResult<()> {
        self.end_page();
        let mut warnings = Vec::new();
        let mut doc = PdfDocument::new(title);
        doc.with_pages(self.pages);
        let bytes = doc.save(&PdfSaveOptions::default(), &mut warnings);
        for w in &warnings {
            info!("printpdf warning while writing {:?}: {:?}", output, w);
        }
        // `save` to bytes rather than `save_writer` to a File: `save_writer`
        // returns `()`, so a short write or a full disk would leave a truncated
        // PDF behind with no error. `fs::write` reports it.
        std::fs::write(output, bytes).map_err(ares_core::AresError::Io)
    }
}

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
    let mut c = Canvas::new();

    // Title
    c.line("ARES V3 Benchmark Report", 18.0, true);
    c.line("Ground-truth benchmark vs Trident Arena", 10.0, false);
    c.gap(5.0);

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

    c.line("Summary", 14.0, true);
    c.line(&format!("Protocols Tested: {}", total_tested), 10.0, false);
    c.line(
        &format!("Total Detections: {}", total_detections),
        10.0,
        false,
    );
    c.line(
        &format!("Avg Detection Rate: {:.1}%", avg_rate * 100.0),
        10.0,
        false,
    );
    c.line(
        &format!(
            "Total Economic Impact: {:.4} SOL",
            total_economic as f64 / 1_000_000_000.0
        ),
        10.0,
        false,
    );
    c.line(
        &format!(
            "Precision: {:.2} | Recall: {:.2} | F1: {:.2}",
            avg_precision, avg_recall, avg_f1
        ),
        10.0,
        false,
    );
    c.gap(5.0);

    let results = json
        .get("results")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    // Segment A
    c.line(
        "Segment A: Stub Regression Suite (Deterministic Pattern Validation)",
        12.0,
        true,
    );
    c.line(
        "100-150 LOC reproduction stubs. 100% detection is the design goal — regression suite.",
        9.0,
        false,
    );
    c.gap(2.0);

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
        let (detected, total, rate) = detection_rate(r);
        c.line(
            &format!("  {} — {}/{} ({:.0}%)", name, detected, total, rate),
            10.0,
            false,
        );
    }
    c.gap(5.0);

    // Segment B
    c.line(
        "Segment B: Real-World Capability Assessment (Production 10K+ LOC Repos)",
        12.0,
        true,
    );
    c.line("Honest underperformance (<100%, >0% FP) expected with Phase-1 regex/heuristics on macro-heavy code.", 9.0, false);
    c.gap(2.0);

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
        let (detected, total, rate) = detection_rate(r);
        let (precision, recall, f1, time) = scores(r);
        c.line(
            &format!(
                "  {} — {}/{} ({:.0}%) | P:{:.2} R:{:.2} F1:{:.2} | {}s",
                name, detected, total, rate, precision, recall, f1, time
            ),
            10.0,
            false,
        );
    }
    c.gap(5.0);

    // All protocols
    c.line("Per-Protocol Results (All Protocols)", 12.0, true);
    for r in &results {
        let name = r
            .get("protocol_name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let (detected, total, rate) = detection_rate(r);
        let (precision, recall, f1, time) = scores(r);
        c.line(
            &format!(
                "  {} — {}/{} ({:.1}%) P:{:.2} R:{:.2} F1:{:.2} {}s",
                name, detected, total, rate, precision, recall, f1, time
            ),
            10.0,
            false,
        );
    }
    c.gap(5.0);

    // Footer
    c.line(
        "Generated by ARES V3 — Autonomous Solana Security Auditor",
        9.0,
        false,
    );
    c.line(
        "Pure-Rust PDF generation (printpdf) — no external browser or binary dependencies.",
        9.0,
        false,
    );

    c.save("ARES V3 Benchmark Report", output)
}

/// `total` is clamped to at least 1 so a protocol with no critical/high findings
/// reports 0% rather than dividing by zero into NaN.
fn detection_rate(r: &Value) -> (usize, usize, f64) {
    let detected = r
        .get("detected_critical_high")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let total = r
        .get("total_critical_high")
        .and_then(|v| v.as_u64())
        .unwrap_or(1)
        .max(1) as usize;
    (detected, total, (detected as f64 / total as f64) * 100.0)
}

fn scores(r: &Value) -> (f64, f64, f64, u64) {
    (
        r.get("precision").and_then(|v| v.as_f64()).unwrap_or(0.0),
        r.get("recall").and_then(|v| v.as_f64()).unwrap_or(0.0),
        r.get("f1_score").and_then(|v| v.as_f64()).unwrap_or(0.0),
        r.get("execution_time_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    )
}

/// Generate a simple PDF audit report from an `AuditReport`.
/// Pure Rust — no external binaries.
pub fn generate_scan_pdf(report: &ares_core::AuditReport, output: &Path) -> AresResult<()> {
    let mut c = Canvas::new();

    c.line(
        &format!("ARES V3 Security Audit Report — {}", report.target.name),
        16.0,
        true,
    );
    c.line(
        &format!(
            "Date: {} | Version: {} | Duration: {}s",
            report.metadata.generated_at,
            report.metadata.ares_version,
            report.metadata.scan_duration_secs
        ),
        10.0,
        false,
    );
    c.gap(5.0);

    c.line("Summary", 14.0, true);
    c.line(
        &format!(
            "Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
            report.summary.critical_count,
            report.summary.high_count,
            report.summary.medium_count,
            report.summary.low_count,
            report.summary.informational_count
        ),
        10.0,
        false,
    );
    c.gap(5.0);

    c.line("Findings", 14.0, true);
    for (i, finding) in report.findings.iter().enumerate() {
        c.line(
            &format!("{}. {} [{}]", i + 1, finding.title, finding.severity),
            11.0,
            true,
        );
        c.line(
            &format!(
                "   Category: {} | Confidence: {:.0}%",
                finding.category,
                finding.confidence * 100.0
            ),
            10.0,
            false,
        );
        c.line(
            &format!("   {}", finding.description.replace('\n', " ")),
            9.0,
            false,
        );
        c.line(
            &format!(
                "   Recommendation: {}",
                finding.recommendation.replace('\n', " ")
            ),
            9.0,
            false,
        );
        c.gap(2.0);
    }

    c.gap(3.0);
    c.line(
        "Generated by ARES V3 — Autonomous Solana Security Auditor",
        9.0,
        false,
    );
    c.line(
        "Pure-Rust PDF generation (printpdf) — no external browser or binary dependencies.",
        9.0,
        false,
    );

    let title = format!("ARES Audit Report — {}", report.target.name);
    c.save(&title, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("ares-pdf-test-{}-{}.pdf", name, std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// A PDF that a reader will open starts with the %PDF- header and ends with
    /// the %%EOF trailer. Asserting only "file is non-empty" would pass on a
    /// truncated write, which is the failure `fs::write` exists to catch.
    fn assert_valid_pdf(path: &std::path::Path) -> Vec<u8> {
        let bytes = std::fs::read(path).expect("pdf written");
        assert!(
            bytes.starts_with(b"%PDF-"),
            "missing PDF header, got {:?}",
            &bytes[..bytes.len().min(16)]
        );
        assert!(
            bytes.windows(5).any(|w| w == b"%%EOF"),
            "missing %%EOF trailer — file is truncated"
        );
        bytes
    }

    #[test]
    fn canvas_breaks_a_page_before_writing_off_the_bottom() {
        let mut c = Canvas::new();
        // 10pt lines advance 4mm each; (280-15)/4 ≈ 67 fit before the cursor
        // crosses the bottom margin.
        for i in 0..200 {
            c.line(&format!("line {}", i), 10.0, false);
        }
        assert!(
            c.pages.len() >= 2,
            "200 lines must not fit on one A4 page, got {} page(s)",
            c.pages.len()
        );
        assert!(
            c.y >= CURSOR_BOTTOM - 4.0,
            "cursor ran past the bottom margin: {}",
            c.y
        );
    }

    #[test]
    fn every_line_survives_the_page_break() {
        let mut c = Canvas::new();
        for i in 0..200 {
            c.line(&format!("line {}", i), 10.0, false);
        }
        c.end_page();
        let shown: usize = c
            .pages
            .iter()
            .flat_map(|p| p.ops.iter())
            .filter(|op| matches!(op, Op::ShowText { .. }))
            .count();
        assert_eq!(shown, 200, "page break dropped lines");
    }

    #[test]
    fn benchmark_pdf_is_readable_with_an_empty_document() {
        let out = tmp("bench-empty");
        build_pdf(&json!({}), &out).expect("empty benchmark json must still render");
        assert_valid_pdf(&out);
        std::fs::remove_file(&out).ok();
    }

    #[test]
    fn benchmark_pdf_renders_results() {
        let out = tmp("bench-full");
        let doc = json!({
            "summary": {
                "total_tested": 3,
                "total_detections": 7,
                "avg_detection_rate": 0.5,
                "total_economic_score_lamports": 1_500_000_000u64,
                "avg_precision": 0.9, "avg_recall": 0.4, "avg_f1_score": 0.55
            },
            "results": [
                {"protocol_name": "type-cosplay", "detected_critical_high": 2,
                 "total_critical_high": 2, "precision": 1.0, "recall": 1.0,
                 "f1_score": 1.0, "execution_time_secs": 3},
                {"protocol_name": "axelar", "detected_critical_high": 1,
                 "total_critical_high": 4, "precision": 0.5, "recall": 0.25,
                 "f1_score": 0.33, "execution_time_secs": 41}
            ]
        });
        build_pdf(&doc, &out).expect("render");
        assert_valid_pdf(&out);
        std::fs::remove_file(&out).ok();
    }

    /// `total_critical_high: 0` would divide by zero; the `.max(1)` clamp is the
    /// only thing keeping "0%" out of being "NaN%" in a customer-facing report.
    #[test]
    fn detection_rate_never_divides_by_zero() {
        let (d, t, rate) = detection_rate(&json!({
            "detected_critical_high": 0, "total_critical_high": 0
        }));
        assert_eq!((d, t), (0, 1));
        assert!(rate.is_finite(), "rate must not be NaN/inf, got {}", rate);
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn detection_rate_and_scores_default_when_fields_are_absent() {
        let (d, t, rate) = detection_rate(&json!({}));
        assert_eq!((d, t, rate), (0, 1, 0.0));
        let (p, r, f1, secs) = scores(&json!({}));
        assert_eq!((p, r, f1, secs), (0.0, 0.0, 0.0, 0));
    }

    /// Wrong-typed JSON (strings where numbers belong) must degrade to defaults
    /// rather than panic — benchmark JSON is read from disk and may be hand-edited.
    #[test]
    fn malformed_field_types_fall_back_instead_of_panicking() {
        let (d, t, rate) = detection_rate(&json!({
            "detected_critical_high": "seven", "total_critical_high": null
        }));
        assert_eq!((d, t, rate), (0, 1, 0.0));
        let (p, ..) = scores(&json!({"precision": "high"}));
        assert_eq!(p, 0.0);
    }

    #[test]
    fn writing_to_an_unwritable_path_reports_an_error() {
        let bad = std::path::Path::new("/nonexistent-dir-ares-test/out.pdf");
        let err = build_pdf(&json!({}), bad).expect_err("must not silently succeed");
        assert!(
            matches!(err, ares_core::AresError::Io(_)),
            "expected an Io error, got {:?}",
            err
        );
    }
}
