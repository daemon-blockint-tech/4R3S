use std::path::PathBuf;

/// Integration test: verify `ares dashboard` generates a self-contained HTML file
/// from a benchmark JSON output.
#[tokio::test]
async fn test_dashboard_generates_html() {
    // Use a known-good benchmark output produced by the benchmark integration test
    let dataset_parent = PathBuf::from("../../dataset");
    let benchmark_output = PathBuf::from("../../ares-dashboard-test-input.json");
    let dashboard_output = PathBuf::from("../../ares-dashboard-test-output.html");

    // Clean up prior artifacts
    let _ = tokio::fs::remove_file(&benchmark_output).await;
    let _ = tokio::fs::remove_file(&dashboard_output).await;

    // First run benchmark to produce real JSON
    ares_v3::commands::benchmark::execute(&dataset_parent, None, true, &benchmark_output)
        .await
        .expect("Benchmark must succeed to produce dashboard input");

    assert!(
        benchmark_output.exists(),
        "Benchmark JSON should have been created"
    );

    // Now generate dashboard
    ares_v3::commands::dashboard::execute(
        &benchmark_output,
        &dashboard_output,
        ares_v3::ReportFormat::Html,
    )
    .await
    .expect("Dashboard generation should succeed");

    assert!(
        dashboard_output.exists(),
        "Dashboard HTML should have been created"
    );

    let html = tokio::fs::read_to_string(&dashboard_output)
        .await
        .expect("Should be able to read generated HTML");

    // Verify self-contained dashboard characteristics
    assert!(
        html.contains("ARES V3 Benchmark Dashboard"),
        "HTML should contain dashboard title"
    );
    assert!(
        html.contains("Detection Rate Comparison"),
        "HTML should contain comparison section"
    );
    assert!(
        html.contains("Per-Protocol Results"),
        "HTML should contain per-protocol table"
    );
    assert!(html.contains("ARES V3"), "HTML should reference ARES");
    assert!(
        html.contains("Trident Arena"),
        "HTML should reference Trident Arena baseline"
    );
    // Self-contained: no external script/link tags
    assert!(
        !html.contains("<script src="),
        "Dashboard should not load external scripts"
    );
    assert!(
        !html.contains("<link rel=\"stylesheet\" href="),
        "Dashboard should not load external stylesheets"
    );

    // Cleanup
    let _ = tokio::fs::remove_file(&benchmark_output).await;
    let _ = tokio::fs::remove_file(&dashboard_output).await;
}
