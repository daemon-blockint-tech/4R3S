# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **VulnerabilityCategory enum**: Replaced all stringly-typed vulnerability categories with a type-safe enum in `ares-core`. Categories are now `VulnerabilityCategory::SignerAuthorization` instead of `"signer-authorization"`. Includes `Display`, `Serialize`, `Deserialize`, `from_str_checked()`, and `all()` implementations.
- **Benchmark dataset**: Created `dataset/solana-common-attack-vectors/` with 11 deterministic stubs (Segment A) and 9 real protocol placeholders (Segment B) with `ground_truth.json`.
- **CI security auditing**: Added `cargo audit` and `cargo deny` jobs to CI workflow.
- **MSRV**: Added `rust-version = "1.75"` to workspace `Cargo.toml`.
- **deny.toml**: Configuration for `cargo deny` with license allowlist and source restrictions.

### Changed
- **Error handling**: Replaced all production `unwrap()` calls with proper error handling:
  - `agent.rs`: LLM tool call JSON parsing now gracefully continues on malformed data instead of panicking.
  - `llm_judge.rs`: `partial_cmp` on `f64` now uses `unwrap_or(Equal)` for NaN safety.
  - `tui/app.rs`: `App::new()` now returns `Result<Self>` instead of panicking.
  - `commands/validate.rs`: `project_root` uses `match` instead of `unwrap()`.
  - `commands/benchmark.rs`: `first()`/`last()` use `map_or` instead of `unwrap()`.
- **API key masking**: TUI status bar and `llm status` command now fully mask API keys as `****` instead of exposing fragments (`XXXX...YYYY`).
- **Test crate references**: All integration tests now use correct crate name `ares_v3` instead of `ares_cli`.
- **Local judge**: Updated to use `VulnerabilityCategory` enum matching instead of string comparison.
- **Validator**: Updated to use `VulnerabilityCategory` enum matching.
- **Scorer**: Updated to use `VulnerabilityCategory` enum matching.
- **PoC generator**: Updated to use `VulnerabilityCategory` enum matching.
- **LLM judge**: Updated prompt builder and category context to use `VulnerabilityCategory` enum.

### Removed
- **tokio-process**: Removed deprecated `tokio-process` dependency from `ares-trident` (functionality merged into `tokio` 1.x).

### Fixed
- **Release workflow**: Removed `|| true` from `cargo publish` commands so publish failures are properly reported.
- **Integration tests**: Fixed pre-existing test failures caused by missing benchmark dataset.

### Security
- **API key exposure**: Eliminated API key fragment leakage in TUI status bar.
- **Panic prevention**: Replaced unsafe `unwrap()` chains in LLM JSON parsing that could crash the CLI on malformed responses.

## [0.1.0] - 2026-05-10
### Added
- Initial implementation of the 4-phase deterministic static analysis pipeline.
- `ares-mapper` with AST parsing (`syn` + `proc-macro2`) and intra-procedural taint tracking.
- `ares-policy` engine with IronCurtain-style sandbox boundaries.
- `ares-trident` integration for SVM-based fuzzing and PoC execution.
- Economic exploit scorer (SCONE-bench inspired).
- Benchmarking system with 11 stubs (Segment A) and 9 production repos (Segment B).
- LLM-as-Judge validation support (optional, requires API key).
- Interactive Agentic TUI for conversational security auditing.
- CLI commands: `scan`, `benchmark`, `fuzz`, `validate`, `report`, `pdf`, `doctor`, `init`.
- Policy guardrails with IronCurtain-style sandbox boundaries.
- Deterministic local judge (Phase 4) with extended v29 heuristics.
- Cross-instruction analysis for TOCTOU and reentrancy risks.
- Proof-of-concept test harness generation.
- Trident Arena head-to-head comparison reporting.
