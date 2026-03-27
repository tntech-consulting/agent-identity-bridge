# AIB Cloud — Managed SaaS Backend

## Architecture

```
cloud/
├── edge-functions/       # Supabase Edge Functions (Deno/TypeScript)
│   ├── auth/            # signup, login, generate_key
│   ├── passport-create/ # Create passport with policy enforcement + Ed25519 signing
│   ├── passport-list/   # List passports (paginated, filterable)
│   ├── passport-revoke/ # Revoke with cascade + separation of duties
│   ├── translate/       # A2A ↔ MCP ↔ AG-UI credential translation (<1ms)
│   ├── usage-check/     # Real-time usage & quota dashboard
│   ├── usage-history/   # Daily activity aggregation for analytics
│   └── policy-manage/   # CRUD for policy rules (12 types)
│   ├── webhook-manage/  # CRUD webhooks (4 event types, HMAC signing)
│   ├── blog-api/        # Blog articles API (EN/FR, auto-publish)
│   ├── blog-scheduler/  # Auto-generate new articles from topic pool
│   └── oidc-test/       # 10-point OIDC federation test suite
├── landing/             # Static HTML pages (deployed on Netlify)
│   ├── index.html       # SaaS landing (aib-cloud.netlify.app)
│   ├── dashboard.html   # Dashboard with auth + 6 tabs
│   ├── frameworks.html  # Framework integrations hub
│   ├── aib-tech-index.html  # Protocol site (aib-tech.fr)
│   ├── pricing.html     # Pricing page
│   └── blog.html        # Blog section (EN/FR, SEO)
└── schema/              # PostgreSQL schema
    └── schema.sql       # 10 tables + RLS + triggers + pg_cron
```

## Supabase Project

- **Project ID**: `vempwtzknixfnvysmiwo`
- **Region**: eu-west-1
- **Base URL**: `https://vempwtzknixfnvysmiwo.supabase.co/functions/v1/`

## Edge Functions (8 total)

| Function | Method | Auth | Description |
|----------|--------|------|-------------|
| `auth` | POST | None | signup/login/generate_key |
| `passport-create` | POST | API key or Bearer | Create passport + policy check + Ed25519 receipt |
| `passport-list` | GET | API key or Bearer | List passports (paginated) |
| `passport-revoke` | POST | API key or Bearer | Revoke + cascade + separation_of_duties check |
| `translate` | POST | API key or Bearer | A2A↔MCP↔AG-UI translation |
| `usage-check` | GET | API key or Bearer | Current usage & quotas |
| `usage-history` | GET | API key or Bearer | Daily activity for charts |
| `policy-manage` | GET/POST/DELETE | API key or Bearer | CRUD policy rules |

## Policy Engine (9 rule types)

| Type | Severity | Description |
|------|----------|-------------|
| `deliverable_gate` | block/warn/log | Require capabilities before action |
| `separation_of_duties` | block/warn/log | Prevent self-revoke |
| `attestation_required` | block/warn/log | Require Ed25519 signing |
| `capability_required` | block/warn/log | Agent must have specific capabilities |
| `domain_block` | block | Block specific domains |
| `domain_allow` | block | Allow only specific domains |
| `protocol_restrict` | block | Block specific protocols |
| `tier_restrict` | block | Restrict by passport tier |
| `time_restrict` | block | Time-based access control |

## Netlify Sites

| Site | URL | Content |
|------|-----|---------|
| Protocol | https://aib-tech.fr | Protocol spec, architecture, pricing |
| SaaS | https://aib-cloud.netlify.app | Landing, dashboard, frameworks |
