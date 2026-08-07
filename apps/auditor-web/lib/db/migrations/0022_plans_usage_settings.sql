-- ============================================================
-- Migration 0022: plans, usage_snapshots, user_settings
-- ARES auditor-web dashboard Postgres
-- ============================================================

-- 1. Plans catalog
CREATE TABLE "plans" (
  "code" text PRIMARY KEY NOT NULL,
  "name" text NOT NULL,
  "description" text,
  "price_label" text NOT NULL,
  "price_cents" integer,
  "compute_hours_limit" integer NOT NULL,
  "on_demand_runs_limit" integer NOT NULL,
  "features" jsonb DEFAULT '[]'::jsonb NOT NULL,
  "is_active" boolean DEFAULT true NOT NULL,
  "stripe_price_id" text,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL
);

-- Seed default plans (align with lib/mock/usage.ts)
INSERT INTO "plans" (
  "code", "name", "description", "price_label", "price_cents",
  "compute_hours_limit", "on_demand_runs_limit", "features"
) VALUES
  (
    'free', 'Free', 'Get started with ARES Auditor on the free tier.',
    '$0 / month', 0, 100, 25,
    '["100 compute hours / month", "25 on-demand runs", "Community support", "Single workspace"]'::jsonb
  ),
  (
    'pro', 'Pro', 'For individual developers running regular audits.',
    '$29 / month', 2900, 500, 100,
    '["500 compute hours / month", "100 on-demand runs", "Priority support", "Multiple repos"]'::jsonb
  ),
  (
    'team', 'Team', 'For teams with shared workspaces and higher limits.',
    '$99 / month', 9900, 2000, 500,
    '["2000 compute hours / month", "500 on-demand runs", "Team management", "SSO (coming soon)"]'::jsonb
  );

-- 2. User settings (1:1 UI preferences)
CREATE TABLE "user_settings" (
  "id" text PRIMARY KEY NOT NULL,
  "user_id" text NOT NULL,
  "theme" text DEFAULT 'system' NOT NULL,
  "email_notifications" boolean DEFAULT false NOT NULL,
  "pr_updates" boolean DEFAULT false NOT NULL,
  "timezone" text,
  "locale" text DEFAULT 'en',
  "preferences" jsonb DEFAULT '{}'::jsonb NOT NULL,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL
);

ALTER TABLE "user_settings"
  ADD CONSTRAINT "user_settings_user_id_users_id_fk"
  FOREIGN KEY ("user_id") REFERENCES "public"."users"("id")
  ON DELETE cascade ON UPDATE no action;

CREATE UNIQUE INDEX "user_settings_user_id_idx"
  ON "user_settings" USING btree ("user_id");

-- 3. Usage snapshots (daily aggregation)
CREATE TABLE "usage_snapshots" (
  "id" text PRIMARY KEY NOT NULL,
  "user_id" text NOT NULL,
  "usage_date" date NOT NULL,
  "compute_seconds" integer DEFAULT 0 NOT NULL,
  "on_demand_runs" integer DEFAULT 0 NOT NULL,
  "created_at" timestamp DEFAULT now() NOT NULL,
  "updated_at" timestamp DEFAULT now() NOT NULL
);

ALTER TABLE "usage_snapshots"
  ADD CONSTRAINT "usage_snapshots_user_id_users_id_fk"
  FOREIGN KEY ("user_id") REFERENCES "public"."users"("id")
  ON DELETE cascade ON UPDATE no action;

CREATE UNIQUE INDEX "usage_snapshots_user_id_usage_date_idx"
  ON "usage_snapshots" USING btree ("user_id", "usage_date");

CREATE INDEX "usage_snapshots_user_id_usage_date_desc_idx"
  ON "usage_snapshots" USING btree ("user_id", "usage_date" DESC);

-- 4. Users.plan_id (expand-contract)
ALTER TABLE "users" ADD COLUMN "plan_id" text;

UPDATE "users" SET "plan_id" = 'free' WHERE "plan_id" IS NULL;

ALTER TABLE "users" ALTER COLUMN "plan_id" SET DEFAULT 'free';
ALTER TABLE "users" ALTER COLUMN "plan_id" SET NOT NULL;

ALTER TABLE "users"
  ADD CONSTRAINT "users_plan_id_plans_code_fk"
  FOREIGN KEY ("plan_id") REFERENCES "public"."plans"("code")
  ON DELETE restrict ON UPDATE cascade;

CREATE INDEX "users_plan_id_idx" ON "users" USING btree ("plan_id");

-- 5. Backfill user_settings for existing users
INSERT INTO "user_settings" ("id", "user_id")
SELECT
  substr(md5(random()::text || u.id), 1, 12),
  u.id
FROM "users" u
WHERE NOT EXISTS (
  SELECT 1 FROM "user_settings" us WHERE us.user_id = u.id
);
