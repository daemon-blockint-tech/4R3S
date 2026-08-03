use ares_core::AresError;

/// Integration test: verify `ares doctor` executes dependency detection logic
/// without panic and returns an appropriate result for the current environment.
#[tokio::test]
async fn test_doctor_runs_dependency_detection() {
    let result = ares_v3::commands::doctor::execute().await;

    match result {
        Ok(()) => {
            // If the system has all required tools installed (cargo, rustc,
            // solana, anchor, trident, git), this is a fully configured env.
            // The test passes because doctor detected everything correctly.
        }
        Err(AresError::ToolMissing(msg)) => {
            // Expected on systems missing Solana/Anchor/Trident.
            // This outcome ALSO proves detection logic works — it identified
            // missing required dependencies and reported them accurately.
            assert!(
                !msg.is_empty(),
                "ToolMissing error should contain a descriptive message"
            );
        }
        Err(other) => {
            panic!(
                "Doctor failed with an unexpected error type (not ToolMissing): {}",
                other
            );
        }
    }
}
