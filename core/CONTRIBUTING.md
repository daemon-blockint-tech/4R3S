# Contributing to ARES V3

Thank you for your interest in contributing to ARES V3! We welcome contributions from the community to help make Solana smart contract auditing more secure, deterministic, and accessible.

## Development Workflow

1. **Fork the repository** and create a new branch for your feature or bug fix.
2. **Ensure tests pass** before submitting a PR.
3. **Format your code** using `rustfmt`.
4. **Run `clippy`** to catch common mistakes.

```bash
# Run tests
cargo test

# Format code
cargo fmt --all

# Run linter
cargo clippy --all-targets --all-features -- -D warnings
```

## Project Structure

- `crates/ares-core`: Core data structures, errors, and configuration.
- `crates/ares-mapper`: Phase 2 AST scanner, Phase 3 Taint engine, and Phase 4 Local Judge.
- `crates/ares-policy`: IronCurtain-style policy engine.
- `crates/ares-trident`: Trident SVM integration.
- `crates/ares-cli`: The command-line interface.

## Adding New Heuristics

If you are adding a new detection rule to the AST scanner or Taint engine, please ensure:
1. It is deterministic (does not rely on external non-deterministic sources like LLMs).
2. You provide a test stub in `dataset/solana-common-attack-vectors/stubs/` demonstrating the vulnerability.
3. You update the Phase 4 Local Judge (`crates/ares-mapper/src/local_judge.rs`) if the new rule produces systematic false positives that can be suppressed deterministically.

## Pull Request Process

- Provide a clear and descriptive title.
- Link any relevant issues.
- Explain the "Why" and "How" of your changes.
- If you're changing the detection logic, include benchmark results (`ares benchmark`) showing the impact on precision and recall.

## Code of Conduct

Please be respectful and constructive in issues and code reviews. We adhere to the standard Rust community code of conduct.
