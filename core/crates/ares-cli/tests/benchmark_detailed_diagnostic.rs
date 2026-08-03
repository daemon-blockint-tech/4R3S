/// Detailed diagnostic: shows detected vs expected categories per protocol.
#[tokio::test]
async fn test_benchmark_detailed_diagnostic() {
    use std::collections::HashSet;
    use std::path::PathBuf;

    let dataset = PathBuf::from("../../dataset");
    let output = PathBuf::from("../../ares-benchmark-detailed.json");
    let _ = tokio::fs::remove_file(&output).await;

    let result = ares_v3::commands::benchmark::execute(&dataset, None, true, &output).await;
    assert!(result.is_ok());

    let content = tokio::fs::read_to_string(&output).await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    let results = json.get("results").and_then(|r| r.as_array()).unwrap();
    println!("\n=== ARES Detailed Benchmark Diagnostic ===\n");

    // Load ground truth for expected categories
    let gt_path = dataset
        .join("solana-common-attack-vectors")
        .join("ground_truth.json");
    let gt_content = tokio::fs::read_to_string(&gt_path)
        .await
        .unwrap_or_default();
    let gt: serde_json::Value =
        serde_json::from_str(&gt_content).unwrap_or(serde_json::json!({"protocols": []}));

    for r in results {
        let name = r
            .get("protocol_name")
            .and_then(|n| n.as_str())
            .unwrap_or("unknown");
        let tp = r
            .get("detected_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total = r
            .get("total_critical_high")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let fp = r
            .get("false_positives")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let fn_ = r
            .get("false_negatives")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let rate = r
            .get("detection_rate")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let detected: Vec<String> = r
            .get("detected_categories")
            .and_then(|c| c.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|c| c.as_str().map(|s| s.to_string()))
            .collect();

        // Get expected categories from ground truth
        let expected: HashSet<String> = gt
            .get("protocols")
            .and_then(|p| p.as_array())
            .unwrap_or(&vec![])
            .iter()
            .find(|p| p.get("name").and_then(|n| n.as_str()) == Some(name))
            .and_then(|p| p.get("expected_categories"))
            .and_then(|c| c.as_array())
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|c| c.as_str().map(|s| s.to_string()))
            .collect();

        println!(
            "Protocol: {} | TP={}/{} FP={} FN={} | rate={:.1}%",
            name,
            tp,
            total,
            fp,
            fn_,
            rate * 100.0
        );
        println!("  Expected: {:?}", expected);
        println!("  Detected: {:?}", detected);
    }

    let summary = json.get("summary").unwrap();
    let avg_rate = summary
        .get("avg_detection_rate")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let avg_prec = summary
        .get("avg_precision")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let avg_rec = summary
        .get("avg_recall")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    println!("\n=== Summary ===");
    println!(
        "Avg Detection: {:.1}% | Precision: {:.2} | Recall: {:.2}",
        avg_rate * 100.0,
        avg_prec,
        avg_rec
    );

    let _ = tokio::fs::remove_file(&output).await;
}
