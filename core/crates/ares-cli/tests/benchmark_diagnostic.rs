/// Diagnostic test: run benchmark and print detection rates per protocol.
#[tokio::test]
async fn test_benchmark_diagnostic() {
    use std::path::PathBuf;

    let dataset = PathBuf::from("../../dataset");
    let output = PathBuf::from("../../ares-benchmark-diagnostic.json");
    let _ = tokio::fs::remove_file(&output).await;

    let result = ares_v3::commands::benchmark::execute(&dataset, None, true, &output).await;
    assert!(result.is_ok());

    let content = tokio::fs::read_to_string(&output).await.unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();

    let results = json.get("results").and_then(|r| r.as_array()).unwrap();
    println!("\n=== ARES Benchmark Diagnostic ===\n");
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
        let p = r.get("precision").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let rec = r.get("recall").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let f1 = r.get("f1_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let secs = r
            .get("execution_time_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        println!(
            "{:25} | TP={}/{} FP={} FN={} | rate={:.1}% | P={:.2} R={:.2} F1={:.2} | {}s",
            name,
            tp,
            total,
            fp,
            fn_,
            rate * 100.0,
            p,
            rec,
            f1,
            secs
        );
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
    let avg_f1 = summary
        .get("avg_f1_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    println!("\n=== Summary ===");
    println!("Avg Detection Rate: {:.1}%", avg_rate * 100.0);
    println!("Avg Precision:      {:.2}", avg_prec);
    println!("Avg Recall:         {:.2}", avg_rec);
    println!("Avg F1 Score:       {:.2}", avg_f1);
    println!("Trident Arena Baseline: 70.0% detection, 26.56% FP");

    let _ = tokio::fs::remove_file(&output).await;
}
