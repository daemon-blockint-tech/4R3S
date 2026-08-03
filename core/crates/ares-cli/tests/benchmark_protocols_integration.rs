use std::path::PathBuf;

/// Integration test: verify ground truth contains real-world protocol entries
/// (axelar, dexalot, bert-staking, pump-science, metadao) and the benchmark
/// produces detection metrics for all of them.  Watt is excluded because its
/// source code is not publicly available.
#[tokio::test]
async fn test_benchmark_ground_truth_real_protocols() {
    let dataset = PathBuf::from("../../dataset");
    let output = PathBuf::from("../../ares-benchmark-protocol-test.json");

    // Clean up from prior runs
    let _ = tokio::fs::remove_file(&output).await;

    let result = ares_v3::commands::benchmark::execute(
        &dataset, None, // no protocol filter — test all including stubs
        true, // compare baseline
        &output,
    )
    .await;

    assert!(
        result.is_ok(),
        "Benchmark execution should succeed: {:?}",
        result.err()
    );

    let content = tokio::fs::read_to_string(&output)
        .await
        .expect("Benchmark should have written output file");

    let json: serde_json::Value =
        serde_json::from_str(&content).expect("Benchmark output should be valid JSON");

    let results = json
        .get("results")
        .and_then(|r| r.as_array())
        .expect("JSON should contain 'results' array");

    // Verify all publicly available real-world protocols are present
    let real_protocols = [
        "axelar",
        "dexalot",
        "bert-staking",
        "pump-science",
        "metadao",
    ];
    for name in &real_protocols {
        let entry = results
            .iter()
            .find(|r| r.get("protocol_name").and_then(|n| n.as_str()) == Some(*name));
        assert!(
            entry.is_some(),
            "Benchmark should include {} protocol results",
            name
        );

        let entry = entry.unwrap();
        assert!(
            entry
                .get("total_critical_high")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                > 0,
            "{} should have expected critical/high count > 0",
            name
        );

        let precision = entry.get("precision").and_then(|v| v.as_f64());
        let recall = entry.get("recall").and_then(|v| v.as_f64());
        let f1 = entry.get("f1_score").and_then(|v| v.as_f64());

        assert!(
            precision.is_some(),
            "{} should have precision when ground truth is loaded",
            name
        );
        assert!(
            recall.is_some(),
            "{} should have recall when ground truth is loaded",
            name
        );
        assert!(
            f1.is_some(),
            "{} should have f1_score when ground truth is loaded",
            name
        );
    }

    // Cleanup
    let _ = tokio::fs::remove_file(&output).await;
}
