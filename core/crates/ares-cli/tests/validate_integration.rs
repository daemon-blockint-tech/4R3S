/// Integration test: verify ForkValidator builder constructs correct arguments
/// and gracefully handles missing `solana-test-validator` binary.
#[tokio::test]
async fn test_fork_validator_graceful_missing_binary() {
    let mut validator =
        ares_v3::fork_validator::ForkValidator::builder("https://api.mainnet-beta.solana.com")
            .slot(Some(30_000_000))
            .clone_accounts(vec![
                "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".to_string(),
                "11111111111111111111111111111111".to_string(),
            ])
            .build();

    // On systems without solana-test-validator installed, start() should fail
    // with a descriptive error rather than panic.
    match validator.start().await {
        Err(err) => {
            assert!(
                err.contains("solana-test-validator") || err.contains("Failed to start"),
                "Error should mention validator binary: got '{}'",
                err
            );
        }
        Ok(url) => {
            // If it IS installed, we don't want to leave it running in CI,
            // so we stop immediately.
            assert!(
                url.contains("127.0.0.1:8899"),
                "Local RPC should point to default port: got '{}'",
                url
            );
            validator.stop().await;
        }
    }
}

/// Integration test: verify `ares validate` command gracefully handles missing PoC path.
#[tokio::test]
async fn test_validate_missing_poc_path() {
    let bad_path = std::path::PathBuf::from("/nonexistent/poc_test.rs");
    let config = ares_core::AresConfig::default();

    let result = ares_v3::commands::validate::execute(&bad_path, false, None, &config, None).await;

    assert!(
        result.is_err(),
        "validate should fail when PoC path does not exist"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("not found") || err.contains("NotFound"),
        "Error should indicate missing path: got '{}'",
        err
    );
}
