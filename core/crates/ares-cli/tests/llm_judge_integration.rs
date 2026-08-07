/// Integration test: verify LLM-as-Judge passthrough when disabled.
/// When llm_judge_enabled=false or provider=Disabled, all findings should pass through
/// without suppression and llm_used should be false.
#[tokio::test]
async fn test_llm_judge_disabled_passthrough() {
    // Create a minimal ProgramGraph (empty is sufficient for this test)
    let graph = ares_mapper::ProgramGraph::default();

    let config = ares_core::AresConfig {
        llm_judge_enabled: false,
        llm_provider: ares_core::LlmProvider::Disabled,
        llm_api_key: None,
        ..Default::default()
    };

    let judge = ares_v3::llm_judge::LlmJudge::new(&graph, &config);

    let findings = vec![
        ares_core::Finding {
            id: "TEST-001".to_string(),
            title: "Test finding".to_string(),
            description: "Test description".to_string(),
            severity: ares_core::Severity::High,
            category: ares_core::VulnerabilityCategory::SignerAuthorization,
            location: ares_core::CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "Fix it".to_string(),
            references: vec![],
            confidence: 0.90,
            validation: None,
        },
        ares_core::Finding {
            id: "TEST-002".to_string(),
            title: "Another test finding".to_string(),
            description: "Another test description".to_string(),
            severity: ares_core::Severity::Critical,
            category: ares_core::VulnerabilityCategory::ArbitraryCpi,
            location: ares_core::CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "Fix it too".to_string(),
            references: vec![],
            confidence: 0.85,
            validation: None,
        },
    ];

    let results = judge.validate(findings.clone()).await;

    assert_eq!(
        results.len(),
        2,
        "All findings should be returned even when LLM judge is disabled"
    );

    for (i, result) in results.iter().enumerate() {
        assert!(
            !result.suppressed,
            "Finding {} should NOT be suppressed when LLM is disabled",
            i
        );
        assert!(
            !result.llm_used,
            "llm_used should be false when provider is Disabled"
        );
        assert_eq!(
            result.finding.id, findings[i].id,
            "Finding ID should be preserved"
        );
    }

    let extracted = ares_v3::llm_judge::extract_findings(results);
    assert_eq!(
        extracted.len(),
        2,
        "All findings should be extracted when none are suppressed"
    );
}

/// Integration test: verify scan budget truncates low-confidence findings.
/// When findings exceed `llm_max_findings_per_scan`, only the top-N by confidence
/// are sent to the LLM; the rest are passed through with an explicit budget-skip
/// reason. Without a working LLM backend no finding may be marked `llm_used`.
#[tokio::test]
async fn test_llm_judge_budget_truncation() {
    let graph = ares_mapper::ProgramGraph::default();

    let config = ares_core::AresConfig {
        llm_judge_enabled: true,
        llm_provider: ares_core::LlmProvider::Openai,
        llm_api_key: Some("test-key".to_string()),
        llm_model: "gpt-4".to_string(),
        llm_max_findings_per_scan: 2,
        ..Default::default()
    };

    let judge = ares_v3::llm_judge::LlmJudge::new(&graph, &config);

    let findings = vec![
        // Low confidence — should be skipped
        ares_core::Finding {
            id: "LOW-001".to_string(),
            title: "Low confidence".to_string(),
            description: "desc".to_string(),
            severity: ares_core::Severity::Medium,
            category: ares_core::VulnerabilityCategory::OwnershipCheck,
            location: ares_core::CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "fix".to_string(),
            references: vec![],
            confidence: 0.50,
            validation: None,
        },
        // High confidence — should be evaluated
        ares_core::Finding {
            id: "HIGH-001".to_string(),
            title: "High confidence A".to_string(),
            description: "desc".to_string(),
            severity: ares_core::Severity::Critical,
            category: ares_core::VulnerabilityCategory::SignerAuthorization,
            location: ares_core::CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "fix".to_string(),
            references: vec![],
            confidence: 0.95,
            validation: None,
        },
        // Medium-high confidence — should be evaluated
        ares_core::Finding {
            id: "MED-001".to_string(),
            title: "Medium high".to_string(),
            description: "desc".to_string(),
            severity: ares_core::Severity::High,
            category: ares_core::VulnerabilityCategory::ArbitraryCpi,
            location: ares_core::CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "fix".to_string(),
            references: vec![],
            confidence: 0.80,
            validation: None,
        },
        // Medium confidence — should be skipped (after top 2)
        ares_core::Finding {
            id: "MED-002".to_string(),
            title: "Medium B".to_string(),
            description: "desc".to_string(),
            severity: ares_core::Severity::High,
            category: ares_core::VulnerabilityCategory::ReentrancyRisk,
            location: ares_core::CodeLocation::default(),
            proof_of_concept: None,
            recommendation: "fix".to_string(),
            references: vec![],
            confidence: 0.70,
            validation: None,
        },
    ];

    let results = judge.validate(findings).await;

    assert_eq!(results.len(), 4, "All 4 findings should be returned");

    // The two lowest-confidence findings overflow the budget of 2 and must
    // carry the explicit budget-skip reason.
    let budget_skipped: Vec<_> = results
        .iter()
        .filter(|r| r.reasoning.contains("budget"))
        .collect();
    assert_eq!(
        budget_skipped.len(),
        2,
        "2 findings should be skipped due to budget"
    );

    // Without a working LLM backend (feature off, or unreachable/invalid API)
    // no finding may be recorded as LLM-judged, and none may be suppressed.
    for result in &results {
        assert!(
            !result.llm_used,
            "llm_used must stay false when no real LLM judgment happened"
        );
        assert!(
            !result.suppressed,
            "No finding should be suppressed without a real LLM verdict"
        );
    }

    let extracted = ares_v3::llm_judge::extract_findings(results);
    assert_eq!(
        extracted.len(),
        4,
        "All findings should be extracted — none suppressed by budget truncation"
    );
}

/// Integration test: verify category-specific prompt text exists for known categories.
#[test]
fn test_llm_judge_prompt_specialization() {
    let categories = vec![
        (
            ares_core::VulnerabilityCategory::SignerAuthorization,
            "signer checks",
        ),
        (ares_core::VulnerabilityCategory::ArbitraryCpi, "CPI"),
        (
            ares_core::VulnerabilityCategory::ReentrancyRisk,
            "reentrancy",
        ),
        (
            ares_core::VulnerabilityCategory::InitializationFrontrunning,
            "front-run",
        ),
        (
            ares_core::VulnerabilityCategory::AccountReloading,
            "tombstone",
        ),
        (ares_core::VulnerabilityCategory::AccountDataMatching, "CPI"),
        (
            ares_core::VulnerabilityCategory::DuplicateMutableAccounts,
            "mutable",
        ),
        (
            ares_core::VulnerabilityCategory::TypeCosplay,
            "discriminator",
        ),
        (ares_core::VulnerabilityCategory::PdaPrivileges, "PDA"),
        (ares_core::VulnerabilityCategory::OwnershipCheck, "owner"),
        (ares_core::VulnerabilityCategory::FuzzingCrash, "fuzzing"),
        (
            ares_core::VulnerabilityCategory::InvariantViolation,
            "invariant",
        ),
        (ares_core::VulnerabilityCategory::Generic, "general Solana"),
    ];

    for (category, expected_substring) in categories {
        let context = ares_v3::llm_judge::category_specific_context(&category);
        assert!(
            context
                .to_lowercase()
                .contains(&expected_substring.to_lowercase()),
            "Prompt for category '{}' should contain '{}' (got: {})",
            category,
            expected_substring,
            context
        );
    }
}

/// Integration test: verify LLM-as-Judge never fabricates a verdict when the
/// `llm-judge` feature is compiled out. The finding must be kept with
/// `llm_used=false` and the error captured in the reasoning field — a simulated
/// judgment must not be recorded as a real one.
#[cfg(not(feature = "llm-judge"))]
#[tokio::test]
async fn test_llm_judge_enabled_stub() {
    let graph = ares_mapper::ProgramGraph::default();

    let config = ares_core::AresConfig {
        llm_judge_enabled: true,
        llm_provider: ares_core::LlmProvider::Openai,
        llm_api_key: Some("test-key".to_string()),
        llm_model: "gpt-4".to_string(),
        ..Default::default()
    };

    let judge = ares_v3::llm_judge::LlmJudge::new(&graph, &config);

    let findings = vec![ares_core::Finding {
        id: "TEST-003".to_string(),
        title: "High-confidence finding".to_string(),
        description: "Missing signer check".to_string(),
        severity: ares_core::Severity::High,
        category: ares_core::VulnerabilityCategory::SignerAuthorization,
        location: ares_core::CodeLocation::default(),
        proof_of_concept: None,
        recommendation: "Add signer check".to_string(),
        references: vec![],
        confidence: 0.90,
        validation: None,
    }];

    let results = judge.validate(findings).await;

    assert_eq!(results.len(), 1, "Should return one result");

    let result = &results[0];
    assert!(
        !result.llm_used,
        "llm_used must be false — a stubbed backend is not a real judgment"
    );
    assert!(
        !result.suppressed,
        "Finding should not be suppressed without a real LLM verdict"
    );
    assert!(
        result.reasoning.contains("LLM evaluation error"),
        "Reasoning should capture the missing-feature error: got '{}'",
        result.reasoning
    );

    let extracted = ares_v3::llm_judge::extract_findings(results);
    assert_eq!(
        extracted.len(),
        1,
        "Finding should be extracted when not suppressed"
    );
}

/// Integration test: verify LLM-as-Judge graceful fallback when API key is missing
/// with the `llm-judge` feature enabled. The finding should be kept and llm_used=false.
#[cfg(feature = "llm-judge")]
#[tokio::test]
async fn test_llm_judge_enabled_missing_key_fallback() {
    let graph = ares_mapper::ProgramGraph::default();

    let config = ares_core::AresConfig {
        llm_judge_enabled: true,
        llm_provider: ares_core::LlmProvider::Openai,
        llm_api_key: None,
        llm_model: "gpt-4".to_string(),
        ..Default::default()
    };

    let judge = ares_v3::llm_judge::LlmJudge::new(&graph, &config);

    let findings = vec![ares_core::Finding {
        id: "TEST-004".to_string(),
        title: "Missing key finding".to_string(),
        description: "No API key configured".to_string(),
        severity: ares_core::Severity::High,
        category: ares_core::VulnerabilityCategory::SignerAuthorization,
        location: ares_core::CodeLocation::default(),
        proof_of_concept: None,
        recommendation: "Add API key".to_string(),
        references: vec![],
        confidence: 0.90,
        validation: None,
    }];

    let results = judge.validate(findings).await;

    assert_eq!(results.len(), 1, "Should return one result");

    let result = &results[0];
    assert!(
        !result.suppressed,
        "Should not suppress finding when API call fails"
    );
    assert!(
        !result.llm_used,
        "llm_used should be false when API key is missing"
    );
    assert!(
        result.reasoning.contains("OpenAI API key not configured"),
        "Reasoning should indicate missing API key: got '{}'",
        result.reasoning
    );

    let extracted = ares_v3::llm_judge::extract_findings(results);
    assert_eq!(
        extracted.len(),
        1,
        "Finding should be extracted when not suppressed"
    );
}
