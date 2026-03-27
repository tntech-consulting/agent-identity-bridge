-- AIB Cloud SaaS Schema
-- 9 tables: organizations, org_members, api_keys, passports, receipts, policy_rules, webhooks, usage, federation_trust
-- Generated from live Supabase project vempwtzknixfnvysmiwo

CREATE TABLE IF NOT EXISTS public.api_keys (
  id uuid NOT NULL DEFAULT uuid_generate_v4() PRIMARY KEY,
  org_id uuid NOT NULL,
  name text NOT NULL DEFAULT 'Default'::text,
  key_prefix text NOT NULL,
  key_hash text NOT NULL,
  status text NOT NULL DEFAULT 'active'::text,
  last_used_at timestamp with time zone,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  created_by uuid
);

CREATE TABLE IF NOT EXISTS public.federation_trust (
  id uuid NOT NULL DEFAULT uuid_generate_v4() PRIMARY KEY,
  org_id uuid NOT NULL,
  trusted_issuer text NOT NULL,
  trusted_domain text NOT NULL,
  jwks_uri text,
  trust_score integer NOT NULL DEFAULT 50,
  grade text NOT NULL DEFAULT 'C'::text,
  tx_count integer NOT NULL DEFAULT 0,
  active boolean NOT NULL DEFAULT true,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.org_members (
  id uuid NOT NULL DEFAULT uuid_generate_v4() PRIMARY KEY,
  org_id uuid NOT NULL,
  user_id uuid NOT NULL,
  role text NOT NULL DEFAULT 'member'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.organizations (
  id uuid NOT NULL DEFAULT uuid_generate_v4() PRIMARY KEY,
  name text NOT NULL,
  slug text NOT NULL,
  owner_id uuid NOT NULL,
  plan text NOT NULL DEFAULT 'beta_pro'::text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  max_passports integer NOT NULL DEFAULT 500,
  max_tx_per_month integer NOT NULL DEFAULT 100000,
  max_webhooks integer NOT NULL DEFAULT 20,
  audit_retention_days integer NOT NULL DEFAULT 90
);

CREATE TABLE IF NOT EXISTS public.passports (
  id uuid NOT NULL DEFAULT uuid_generate_v4() PRIMARY KEY,
  org_id uuid NOT NULL,
  passport_id text NOT NULL,
  display_name text NOT NULL,
  issuer text NOT NULL,
  capabilities text[] NOT NULL DEFAULT '{}'::text[],
  protocols text[] NOT NULL DEFAULT '{}'::text[],
  protocol_bindings jsonb NOT NULL DEFAULT '{}'::jsonb,
  tier text NOT NULL DEFAULT 'permanent'::text,
  version integer NOT NULL DEFAULT 1,
  status text NOT NULL DEFAULT 'active'::text,
  token_hash text,
  parent_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  issued_at timestamp with time zone NOT NULL DEFAULT now(),
  expires_at timestamp with time zone NOT NULL,
  revoked_at timestamp with time zone,
  revoke_reason text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now()
);

