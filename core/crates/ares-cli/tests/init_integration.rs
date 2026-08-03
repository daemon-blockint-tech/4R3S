/// Integration test: verify `ares init` creates workspace files and directories.
#[tokio::test]
async fn test_init_creates_config_files_and_directories() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
    let path = temp_dir.path();

    // Run init command
    ares_v3::commands::init::execute(path)
        .await
        .expect("init should succeed in a fresh temp directory");

    // Verify config files created
    let config_path = path.join("ares.toml");
    let policy_path = path.join("ares-policy.toml");
    assert!(config_path.exists(), "ares.toml should be created");
    assert!(policy_path.exists(), "ares-policy.toml should be created");

    // Verify directory structure
    assert!(
        path.join("ares-output").exists(),
        "ares-output dir should be created"
    );
    assert!(
        path.join("ares-output/reports").exists(),
        "reports dir should be created"
    );
    assert!(
        path.join("ares-output/artifacts").exists(),
        "artifacts dir should be created"
    );
    assert!(
        path.join("ares-output/poc").exists(),
        "poc dir should be created"
    );
    assert!(
        path.join("ares-output/benchmark").exists(),
        "benchmark dir should be created"
    );

    // Verify config contents contain expected template markers
    let config = tokio::fs::read_to_string(&config_path).await.unwrap();
    assert!(
        config.contains("ares"),
        "config should contain 'ares' identifier"
    );

    let policy = tokio::fs::read_to_string(&policy_path).await.unwrap();
    assert!(
        policy.contains("policy"),
        "policy should contain 'policy' identifier"
    );
}

/// Integration test: verify `ares init` is idempotent — does not overwrite existing config.
#[tokio::test]
async fn test_init_is_idempotent() {
    let temp_dir = tempfile::tempdir().expect("failed to create temp directory");
    let path = temp_dir.path();

    // Pre-seed a config file
    let custom_config = "# custom config\nversion = \"99.99.99\"\n";
    tokio::fs::write(path.join("ares.toml"), custom_config)
        .await
        .unwrap();

    // Run init
    ares_v3::commands::init::execute(path)
        .await
        .expect("init should succeed even if config exists");

    // Verify original config was NOT overwritten
    let config = tokio::fs::read_to_string(path.join("ares.toml"))
        .await
        .unwrap();
    assert!(
        config.contains("99.99.99"),
        "existing config should be preserved"
    );
}
