import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // The Auditor's suite lives under src/. Scope to it so the root build does
    // NOT glob apps/ares-sec tests (a separate app with its own deps + CI in
    // ares-sec-ci.yml); running those from the root cwd/node_modules fails.
    // scripts/ holds the two CI gates that enforce GOLDEN RULE 1. They are the
    // only guard against their own failure mode — a gate that greps for the
    // wrong string still exits 0 — so they get tests like anything else.
    include: ["src/**/*.test.ts", "scripts/**/*.test.ts"],
    // env.ts validates config at import; supply a dummy key + quiet logs so
    // tests run without a real .env.
    env: {
      OPENROUTER_API_KEY: "test-key-not-used",
      ARES_LOG_LEVEL: "error",
      // Keep the suite hermetic and fast. Where semgrep is actually installed,
      // several test files spawn it in parallel and contend for tens of seconds,
      // so the same suite is green in CI and flaky on a developer laptop. Tests
      // that need a scanner shim their own and set SEMGREP_BIN back to it.
      SEMGREP_BIN: "ares-semgrep-absent-in-tests",
    },
  },
});
