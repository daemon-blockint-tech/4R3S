use std::path::PathBuf;

/// End-to-end integration test: run `ares benchmark` against the real
/// `solana-common-attack-vectors` dataset and verify it produces detection
/// results using real static analysis (no mock data).
#[tokio::test]
async fn test_benchmark_against_solana_attack_vectors() {
    let _dataset = PathBuf::from("../../dataset/solana-common-attack-vectors");

    // We use the parent directory because benchmark.rs looks for
    // `dataset.join("solana-common-attack-vectors")` internally.
    let dataset_parent = PathBuf::from("../../dataset");

    let output = PathBuf::from("../../ares-benchmark-test-output.json");

    // Clean up from prior runs
    let _ = tokio::fs::remove_file(&output).await;

    let result = ares_v3::commands::benchmark::execute(
        &dataset_parent,
        None, // no protocol filter
        true, // compare baseline
        &output,
    )
    .await;

    assert!(
        result.is_ok(),
        "Benchmark execution should succeed: {:?}",
        result.err()
    );

    // Verify the output file exists and contains real measurements
    let content = tokio::fs::read_to_string(&output)
        .await
        .expect("Benchmark should have written output file");

    assert!(
        content.contains("benchmark_version"),
        "Output should contain benchmark metadata"
    );
    assert!(
        content.contains("results"),
        "Output should contain results array"
    );
    assert!(
        content.contains("total_tested"),
        "Output should contain summary statistics"
    );

    assert!(
        content.contains("ground_truth_used"),
        "Output should indicate whether ground truth was used"
    );

    // Parse to ensure it's valid JSON with non-negative detection metrics
    let json: serde_json::Value =
        serde_json::from_str(&content).expect("Benchmark output should be valid JSON");

    let results = json.get("results").and_then(|r| r.as_array());
    assert!(results.is_some(), "JSON should contain 'results' array");

    let results = results.unwrap();
    // The dataset should have at least a few attack vector programs
    assert!(
        !results.is_empty(),
        "Benchmark should test at least one attack vector program"
    );

    let mut any_ground_truth = false;
    for r in results {
        let detection_rate = r
            .get("detection_rate")
            .and_then(|d| d.as_f64())
            .expect("Each result should have a detection_rate");
        assert!(
            (0.0..=1.0).contains(&detection_rate),
            "Detection rate must be in [0.0, 1.0]"
        );

        // Phase 6: precision / recall / f1_score must be present when ground truth loaded
        if let Some(p) = r.get("precision").and_then(|v| v.as_f64()) {
            any_ground_truth = true;
            assert!((0.0..=1.0).contains(&p), "Precision must be in [0.0, 1.0]");
            let rec = r
                .get("recall")
                .and_then(|v| v.as_f64())
                .expect("Recall must accompany precision");
            assert!((0.0..=1.0).contains(&rec), "Recall must be in [0.0, 1.0]");
            let f1 = r
                .get("f1_score")
                .and_then(|v| v.as_f64())
                .expect("F1 score must accompany precision");
            assert!((0.0..=1.0).contains(&f1), "F1 score must be in [0.0, 1.0]");
        }

        let execution_time = r
            .get("execution_time_secs")
            .and_then(|t| t.as_u64())
            .expect("Each result should have execution_time_secs");
        // Real analysis takes some time; accept 0 for very small programs
        assert!(
            execution_time < 300,
            "Single attack vector analysis should complete in <5 minutes"
        );
    }

    // Ensure ground truth was actually loaded (dataset includes ground_truth.json)
    assert!(
        any_ground_truth,
        "Ground truth should have been loaded from dataset/ground_truth.json so that precision/recall are populated"
    );

    // Cleanup
    let _ = tokio::fs::remove_file(&output).await;
}
