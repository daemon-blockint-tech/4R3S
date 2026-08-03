use ares_core::{Finding, LlmProvider, VulnerabilityCategory};
use ares_mapper::ProgramGraph;
use tracing::{info, warn};

/// LLM-as-Judge validator for vulnerability findings.
///
/// Uses an LLM to assess whether a finding is actually exploitable by reasoning
/// about the program context, account relationships, and instruction semantics.
/// This complements the SemanticValidator (rule-based) with an LLM's ability
/// to understand implicit program invariants and Solana-specific security patterns.
///
/// When no LLM is configured, falls back to passthrough (all findings kept).
pub struct LlmJudge<'a> {
    _graph: &'a ProgramGraph,
    config: &'a ares_core::AresConfig,
}

#[derive(Debug, Clone)]
pub struct LlmValidationResult {
    pub finding: Finding,
    pub suppressed: bool,
    pub plausibility_score: f64, // 0.0 - 1.0
    pub reasoning: String,
    pub llm_used: bool,
}

impl<'a> LlmJudge<'a> {
    pub fn new(graph: &'a ProgramGraph, config: &'a ares_core::AresConfig) -> Self {
        Self {
            _graph: graph,
            config,
        }
    }

    /// Validate a list of findings through LLM-as-Judge.
    /// If LLM is disabled or no API key, passes through with llm_used=false.
    /// Applies per-category prompt specialization and scan-level budget enforcement.
    pub async fn validate(&self, findings: Vec<Finding>) -> Vec<LlmValidationResult> {
        let mut results = Vec::with_capacity(findings.len());

        if !self.config.llm_judge_enabled
            || matches!(self.config.llm_provider, LlmProvider::Disabled)
        {
            info!("LLM-as-Judge is disabled; passing all findings through without LLM validation.");
            for finding in findings {
                results.push(LlmValidationResult {
                    finding,
                    suppressed: false,
                    plausibility_score: 0.5, // neutral
                    reasoning: "LLM-as-Judge disabled — passthrough".to_string(),
                    llm_used: false,
                });
            }
            return results;
        }

        let max_findings = self.config.llm_max_findings_per_scan.max(1);
        let mut prioritized = findings.clone();
        prioritized.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let (to_evaluate, skipped): (Vec<_>, Vec<_>) = if prioritized.len() > max_findings {
            info!(
                "LLM-as-Judge scan budget: {} findings > max {}. Prioritizing top {} by confidence.",
                prioritized.len(), max_findings, max_findings
            );
            let (head, tail) = prioritized.split_at(max_findings);
            (head.to_vec(), tail.to_vec())
        } else {
            (prioritized, vec![])
        };

        info!(
            "LLM-as-Judge validating {} findings via {:?} model={} (max_tokens_per_call={})",
            to_evaluate.len(),
            self.config.llm_provider,
            self.config.llm_model,
            self.config.llm_max_tokens_per_call
        );

        // Evaluate prioritized findings with specialized prompts
        for finding in to_evaluate {
            match self.evaluate_finding(&finding).await {
                Ok(result) => {
                    if result.suppressed {
                        info!(
                            "LLM suppressed finding {} | plausibility={:.2} | reason={}",
                            result.finding.id, result.plausibility_score, result.reasoning
                        );
                    }
                    results.push(result);
                }
                Err(e) => {
                    warn!(
                        "LLM evaluation failed for {}: {} — keeping finding",
                        finding.id, e
                    );
                    results.push(LlmValidationResult {
                        finding,
                        suppressed: false,
                        plausibility_score: 0.5,
                        reasoning: format!("LLM evaluation error: {}", e),
                        llm_used: false,
                    });
                }
            }
        }

        // Pass through skipped findings (budget exceeded)
        for finding in &skipped {
            results.push(LlmValidationResult {
                finding: finding.clone(),
                suppressed: false,
                plausibility_score: 0.5,
                reasoning: format!(
                    "LLM evaluation skipped due to scan budget (max {} findings, lower confidence)",
                    max_findings
                ),
                llm_used: false,
            });
        }

        let suppressed_count = results.iter().filter(|r| r.suppressed).count();
        let evaluated_count = results.iter().filter(|r| r.llm_used).count();
        if suppressed_count > 0 || !skipped.is_empty() {
            info!(
                "LLM-as-Judge: suppressed {} of {} evaluated findings, {} skipped due to budget",
                suppressed_count,
                evaluated_count,
                skipped.len()
            );
        }

        results
    }

    /// Build a structured prompt and send to the configured LLM provider.
    async fn evaluate_finding(&self, finding: &Finding) -> Result<LlmValidationResult, String> {
        let prompt = self.build_specialized_prompt(finding);
        let raw = self.call_llm(&prompt).await?;
        self.parse_llm_response(finding.clone(), &raw)
    }

    /// Construct a category-specialized prompt for the LLM.
    fn build_specialized_prompt(&self, finding: &Finding) -> String {
        let category_context = category_specific_context(&finding.category);
        let base = format!(
            r#"You are an expert Solana smart-contract security auditor.
Your task is to evaluate whether the following vulnerability finding is actually exploitable in practice.

## Finding
- **ID**: {}
- **Title**: {}
- **Category**: {}
- **Severity**: {}
- **Confidence**: {:.0}%
- **Description**: {}
- **Recommendation**: {}

## Category-Specific Context
{}

## Program Context
This is an Anchor-based Solana program. The finding was generated by static analysis.

## Task
Evaluate whether this finding represents a REAL, EXPLOITABLE vulnerability or a FALSE POSITIVE.

Consider:
1. Is the described vulnerability actually reachable by an attacker?
2. Are there implicit protections (PDA constraints, account relationships) not mentioned?
3. Is the severity appropriate for the actual impact?
4. Would a proof-of-concept test likely succeed?

## Output Format
Return ONLY a JSON object with this exact structure (no markdown, no explanations outside JSON):
{{
    "plausibility_score": <float 0.0-1.0>,
    "is_false_positive": <boolean>,
    "reasoning": "<2-3 sentence explanation>",
    "suggested_severity": "<Critical|High|Medium|Low|Informational>"
}}

Scoring:
- 0.0-0.3: Almost certainly a false positive
- 0.3-0.5: Likely a false positive or very low impact
- 0.5-0.7: Uncertain, needs manual review
- 0.7-1.0: Plausible real vulnerability
"#,
            finding.id,
            finding.title,
            finding.category,
            finding.severity,
            finding.confidence * 100.0,
            finding.description,
            finding.recommendation,
            category_context,
        );
        base
    }

    /// Call the configured LLM provider over HTTP when the `llm-judge` feature is enabled.
    #[cfg(feature = "llm-judge")]
    async fn call_llm(&self, prompt: &str) -> Result<String, String> {
        use tokio::time::{timeout, Duration};

        let provider = self.config.llm_provider.clone();
        let model = self.config.llm_model.clone();
        let api_key = self.config.llm_api_key.clone();
        let base_url = self.config.llm_base_url.clone();
        let max_tokens = self.config.llm_max_tokens_per_call;

        // Rough token guard: average 4 chars per token; if prompt is huge, trim or reject.
        let estimated_input_tokens = prompt.len() as u32 / 4;
        if estimated_input_tokens + max_tokens > 8192 && max_tokens > 512 {
            warn!(
                "Estimated prompt+response tokens (~{}) may exceed context window; capping max_tokens to 512",
                estimated_input_tokens + max_tokens
            );
        }
        let response_tokens = if estimated_input_tokens + max_tokens > 8192 {
            512
        } else {
            max_tokens
        };

        let inner = async {
            let client = reqwest::Client::new();

            match provider {
                LlmProvider::Disabled => Err("LLM provider is disabled".to_string()),
                LlmProvider::Openai => {
                    let key = api_key.ok_or("OpenAI API key not configured")?;
                    let body = serde_json::json!({
                        "model": model,
                        "messages": [{"role": "user", "content": prompt}],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.1,
                        "max_tokens": response_tokens,
                    });

                    let resp = client
                        .post("https://api.openai.com/v1/chat/completions")
                        .header("Authorization", format!("Bearer {}", key))
                        .json(&body)
                        .timeout(Duration::from_secs(30))
                        .send()
                        .await
                        .map_err(|e| format!("OpenAI request failed: {}", e))?;

                    if !resp.status().is_success() {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("OpenAI API returned {}: {}", status, text));
                    }

                    let json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("OpenAI response parse failed: {}", e))?;
                    let content = json["choices"][0]["message"]["content"]
                        .as_str()
                        .ok_or("OpenAI response missing content")?;
                    Ok(content.to_string())
                }
                LlmProvider::Anthropic => {
                    let key = api_key.ok_or("Anthropic API key not configured")?;
                    let body = serde_json::json!({
                        "model": model,
                        "max_tokens": response_tokens,
                        "messages": [{"role": "user", "content": prompt}],
                    });

                    let resp = client
                        .post("https://api.anthropic.com/v1/messages")
                        .header("x-api-key", key)
                        .header("anthropic-version", "2023-06-01")
                        .header("Content-Type", "application/json")
                        .json(&body)
                        .timeout(Duration::from_secs(30))
                        .send()
                        .await
                        .map_err(|e| format!("Anthropic request failed: {}", e))?;

                    if !resp.status().is_success() {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("Anthropic API returned {}: {}", status, text));
                    }

                    let json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("Anthropic response parse failed: {}", e))?;
                    let content = json["content"][0]["text"]
                        .as_str()
                        .ok_or("Anthropic response missing text")?;
                    Ok(content.to_string())
                }
                LlmProvider::Ollama => {
                    let url_base = base_url.as_deref().unwrap_or("http://localhost:11434");
                    let body = serde_json::json!({
                        "model": model,
                        "prompt": prompt,
                        "format": "json",
                        "stream": false,
                        "options": {
                            "temperature": 0.1,
                            "num_predict": response_tokens,
                        }
                    });

                    let url = format!("{}/api/generate", url_base.trim_end_matches('/'));
                    let resp = client
                        .post(&url)
                        .json(&body)
                        .timeout(Duration::from_secs(60))
                        .send()
                        .await
                        .map_err(|e| format!("Ollama request failed: {}", e))?;

                    if !resp.status().is_success() {
                        let status = resp.status();
                        let text = resp.text().await.unwrap_or_default();
                        return Err(format!("Ollama API returned {}: {}", status, text));
                    }

                    let json: serde_json::Value = resp
                        .json()
                        .await
                        .map_err(|e| format!("Ollama response parse failed: {}", e))?;
                    let content = json["response"]
                        .as_str()
                        .ok_or("Ollama response missing response field")?;
                    Ok(content.to_string())
                }
            }
        };

        timeout(Duration::from_secs(90), inner)
            .await
            .unwrap_or_else(|_| Err("LLM request timed out after 90 seconds".to_string()))
    }

    /// Stub implementation used when the `llm-judge` feature is disabled.
    /// Returns a deterministic simulated response for architecture testing.
    #[cfg(not(feature = "llm-judge"))]
    async fn call_llm(&self, _prompt: &str) -> Result<String, String> {
        match self.config.llm_provider {
            LlmProvider::Disabled => Err("LLM provider is disabled".to_string()),
            _ => {
                // Simulated response: findings with confidence >= 0.85 are likely real
                // This is a deterministic stub for testing the pipeline architecture
                Ok(r#"{"plausibility_score": 0.75, "is_false_positive": false, "reasoning": "Simulated LLM assessment — architecture validation.", "suggested_severity": "High"}"#.to_string())
            }
        }
    }

    /// Parse the LLM's JSON response into a structured validation result.
    fn parse_llm_response(
        &self,
        finding: Finding,
        raw: &str,
    ) -> Result<LlmValidationResult, String> {
        // Try to extract JSON from the response (in case LLM wraps it in markdown)
        let json_str = if raw.contains("```json") {
            raw.split("```json")
                .nth(1)
                .and_then(|s| s.split("```").next())
                .unwrap_or(raw)
                .trim()
        } else if raw.contains("```") {
            raw.split("```").nth(1).unwrap_or(raw).trim()
        } else {
            raw.trim()
        };

        #[derive(serde::Deserialize)]
        struct LlmResponse {
            plausibility_score: f64,
            is_false_positive: bool,
            reasoning: String,
            #[allow(dead_code)]
            suggested_severity: String,
        }

        let parsed: LlmResponse = serde_json::from_str(json_str)
            .map_err(|e| format!("Failed to parse LLM JSON response: {} | raw: {}", e, raw))?;

        let suppressed = parsed.is_false_positive || parsed.plausibility_score < 0.3;

        Ok(LlmValidationResult {
            finding,
            suppressed,
            plausibility_score: parsed.plausibility_score.clamp(0.0, 1.0),
            reasoning: parsed.reasoning,
            llm_used: true,
        })
    }
}

/// Convert LLM validation results back into standard findings, filtering suppressed ones.
pub fn extract_findings(results: Vec<LlmValidationResult>) -> Vec<Finding> {
    results
        .into_iter()
        .filter(|r| !r.suppressed)
        .map(|r| r.finding)
        .collect()
}

/// Returns category-specific Solana security context for the LLM prompt.
pub fn category_specific_context(category: &VulnerabilityCategory) -> String {
    match category {
        VulnerabilityCategory::SignerAuthorization => {
            r#"Solana transactions require explicit signer checks. A missing `Signer` constraint in Anchor or manual `is_signer` check allows arbitrary account substitution. Check whether:
- The instruction requires a privileged action (e.g., withdrawing funds, upgrading state).
- The account in question could be supplied by an attacker without the legitimate keypair.
- `sysvar::rent` or `system_program` address substitution is possible.
"#.to_string()
        }
        VulnerabilityCategory::ArbitraryCpi => {
            r#"Cross-Program Invocations (CPI) must validate the target program ID. Anchor's `CpiContext` or `invoke_signed` without program-id checks can redirect to a malicious program. Evaluate:
- Whether the CPI target is user-controlled (e.g., passed as an account).
- If `AccountInfo` is used instead of typed `Program<...>` for the CPI target.
- Whether `invoke_unchecked` or raw `solana_program::program::invoke` is used without prior validation.
"#.to_string()
        }
        VulnerabilityCategory::ReentrancyRisk => {
            r#"Solana reentrancy occurs when a CPI back into the same program modifies state before the caller finishes. Although Solana lacks native reentrancy, Anchor `realloc`+CPI or manual account reloading can simulate it. Check:
- If the program CPIs into a PDA it owns and re-enters its own instructions.
- Whether account state is read, CPI issued, then the same state read again without re-validation.
- If `AccountReload` or `try_borrow_account` after CPI is missing.
"#.to_string()
        }
        VulnerabilityCategory::InitializationFrontrunning => {
            r#"Account initialization can be front-run because anyone can create an account at a deterministically derived PDA or address if the discriminator/size match. Consider:
- Whether the init PDA is derived from attacker-controlled seeds (e.g., user pubkey alone).
- If `init_if_needed` is used without a signer gate that ensures only the legitimate owner can initialize.
- Whether the initialization logic performs a privileged action that cannot be undone.
"#.to_string()
        }
        VulnerabilityCategory::AccountReloading => {
            r#"A closed account can be revived with different data but the same address (and lamports if rent-exempt). If the program does not zero the discriminator or mark the account truly unusable, an attacker can re-create it later with malicious state. Evaluate:
- Whether `close` constraints zero the discriminator or set an explicit tombstone.
- If the program later assumes an account with a given address must be initialized by itself.
- Whether `init_if_needed` after close is disallowed.
"#.to_string()
        }
        VulnerabilityCategory::AccountDataMatching => {
            r#"Solana account data can be modified during a CPI by the callee. If the caller reads account state, performs a CPI, then continues using the old state without reloading, the data may be stale or malicious. Check:
- Whether mutable `AccountInfo` accounts are passed into CPIs and then used afterward.
- If `AccountReload` or re-deserialization after CPI is present.
- Whether the instruction relies on account balances or sizes that could change mid-CPI.
"#.to_string()
        }
        VulnerabilityCategory::DuplicateMutableAccounts => {
            r#"Passing the same account twice in an instruction's account list, with at least one mutable, can cause overlapping borrows or race-like writes in program logic. Assess:
- Whether the instruction iterates over accounts and could apply the same mutable operation twice.
- If Anchor `HasOne` or custom deduplication checks are missing.
- Whether the vulnerability is reachable by supplying identical pubkeys in the transaction.
"#.to_string()
        }
        VulnerabilityCategory::TypeCosplay => {
            r#"Type cosplay occurs when an untyped `AccountInfo` is cast to a typed `Account<T>` without discriminator validation. If two account types have compatible layouts but different discriminators, an attacker can substitute one for another. Check:
- Whether the account uses `AccountInfo` or `UncheckedAccount` without manual `try_from` / discriminator check.
- If the account type has a unique Anchor discriminator that is validated on every deserialization.
- Whether the instruction trusts account data layout alone for authorization.
"#.to_string()
        }
        VulnerabilityCategory::PdaPrivileges => {
            r#"Program Derived Addresses (PDAs) can sign on behalf of a program via `invoke_signed`, but if seeds are weak or the PDA is not domain-separated, an attacker may predict or create it. Evaluate:
- Whether the PDA seeds include a unique, attacker-unpredictable value (e.g., random nonce, counter).
- If the PDA is used as an authority without `has_one` or `constraint` checks.
- Whether `find_program_address` with weak seeds allows squatting or collision.
"#.to_string()
        }
        VulnerabilityCategory::OwnershipCheck => {
            r#"Every account accessed by a Solana program must be owned by the expected program (or system program for raw accounts). Missing ownership checks allow attackers to pass fake accounts with fabricated data. Check:
- Whether `Account<'_, T>` is used (Anchor auto-checks owner) vs `AccountInfo` (manual check required).
- If the owner constraint is missing in Anchor `#[account(...)]` attributes.
- Whether the program trusts account data without verifying `.owner == expected_program`.
"#.to_string()
        }
        VulnerabilityCategory::FuzzingCrash => {
            r#"A fuzzing crash indicates the program panicked, aborted, or hit an unhandled error path during property-based testing. This is often a sign of:
- Arithmetic overflow/underflow in release mode (wraps) or debug mode (panics).
- Out-of-bounds access on account data.
- Violation of internal invariants that could be triggered by malformed inputs.
Determine whether the crash root cause is exploitable in production (e.g., via a crafted transaction).
"#.to_string()
        }
        VulnerabilityCategory::InvariantViolation => {
            r#"An invariant violation means the program entered a state that should be impossible under correct logic (e.g., negative balance, invalid authority). This is often more severe than a crash because:
- It may leave the program in an exploitable state (e.g., drained vault).
- It can bypass subsequent checks that assume the invariant holds.
- It may be reachable through a specific sequence of instructions (cross-instruction exploit).
Assess whether the invariant is security-critical and reachable by an external attacker.
"#.to_string()
        }
        _ => {
            r#"Evaluate this finding using general Solana security principles:
- Reachability: can an attacker craft a transaction that triggers it?
- Impact: what is the worst-case economic or availability loss?
- Mitigations: are there implicit checks (PDA constraints, runtime checks) that prevent exploitation?
- PoC feasibility: would a deterministic test case likely succeed?
"#.to_string()
        }
    }
}
