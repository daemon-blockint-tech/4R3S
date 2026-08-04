import { describe, expect, it } from "vitest";

import {
  describePostgrestError,
  postgrestErrorMeta,
} from "./supabase-error.js";

describe("postgrestErrorMeta", () => {
  it("preserves hint and code for structured logs", () => {
    expect(
      postgrestErrorMeta({
        code: "42501",
        message: "permission denied for table documents",
        hint: "GRANT SELECT ON public.documents TO anon;",
        details: null,
      }),
    ).toEqual({
      code: "42501",
      message: "permission denied for table documents",
      hint: "GRANT SELECT ON public.documents TO anon;",
      details: undefined,
    });
  });
});

describe("describePostgrestError", () => {
  it("includes hint when Postgres provides a fix", () => {
    const text = describePostgrestError({
      code: "42501",
      message: "permission denied for table documents",
      hint: "GRANT SELECT ON public.documents TO anon;",
    });
    expect(text).toContain("[42501]");
    expect(text).toContain("permission denied");
    expect(text).toContain("hint: GRANT SELECT");
  });

  it("works without optional fields", () => {
    expect(describePostgrestError({ message: "boom" })).toBe("boom");
  });
});
