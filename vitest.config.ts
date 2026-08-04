import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // Without this, vitest's default discovery scans the whole tree —
    // harmless while apps/* and packages/* were empty stubs, but once
    // real test files landed there (ENG-1, SEC-1, UI-1), it started
    // picking up ares-sec's own tests too (including its *compiled dist*
    // output). Each workspace member runs its own tests independently;
    // this should only ever cover the root TS agent's own src/.
    include: ["src/**/*.{test,spec}.ts"],
    exclude: ["**/node_modules/**", "apps/**", "packages/**", "core/**"],
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
