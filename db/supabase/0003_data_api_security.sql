-- ARES Data API security hardening.
-- Implements Supabase "Securing your API" guide: explicit grants, RLS, opt-in exposure.
--
-- Architecture:
--   service_role  — ARES agent ingest/recall (bypasses RLS)
--   authenticated — future auditor-web clients (RLS + RBAC policies)
--   anon          — no knowledge-base access

-- ---------------------------------------------------------------------------
-- Opt-in exposure: new objects in public are not auto-granted to API roles
-- ---------------------------------------------------------------------------
alter default privileges for role postgres in schema public
  revoke select, insert, update, delete on tables from anon, authenticated, service_role;

alter default privileges for role postgres in schema public
  revoke execute on functions from anon, authenticated, service_role;

alter default privileges for role postgres in schema public
  revoke usage, select on sequences from anon, authenticated, service_role;

-- ---------------------------------------------------------------------------
-- Revoke broad default grants on existing knowledge + RBAC tables
-- ---------------------------------------------------------------------------
revoke all on table public.documents from anon;
revoke all on table public.chunks from anon;
revoke all on table public.user_roles from anon, authenticated;
revoke all on table public.role_permissions from anon, authenticated;

-- ---------------------------------------------------------------------------
-- Explicit grants — knowledge tables
-- ---------------------------------------------------------------------------
grant select, insert, update, delete on table public.documents to authenticated;
grant select, insert, update, delete on table public.chunks to authenticated;

grant all on table public.documents to service_role;
grant all on table public.chunks to service_role;

-- RBAC tables: server-managed only (service_role bypasses RLS)
grant all on table public.user_roles to service_role;
grant select on table public.role_permissions to service_role;

-- ---------------------------------------------------------------------------
-- RLS on RBAC tables (no client policies — deny anon/authenticated direct access)
-- ---------------------------------------------------------------------------
alter table public.user_roles enable row level security;
alter table public.role_permissions enable row level security;

-- ---------------------------------------------------------------------------
-- Function EXECUTE grants
-- ---------------------------------------------------------------------------
revoke all on function public.hybrid_search(
  text, vector, integer, double precision, double precision, integer
) from public, anon;

grant execute on function public.hybrid_search(
  text, vector, integer, double precision, double precision, integer
) to service_role, authenticated;

revoke all on function public.authorize(app_permission) from public, anon;

grant execute on function public.authorize(app_permission) to authenticated;

-- custom_access_token_hook remains supabase_auth_admin-only (set in 0002_rbac.sql)
