import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // env.ts validates config at import; supply a dummy key + quiet logs so
    // tests run without a real .env.
    env: {
      OPENROUTER_API_KEY: "test-key-not-used",
      ARES_LOG_LEVEL: "error",
    },
  },
});
