# AIB — Quick Start (5 minutes)

## 1. Install

```bash
pip install agent-identity-bridge
```

## 2. Verify everything works

```bash
aib quickstart
```

You should see **6/6 checks passed**. If not, [open an issue](https://github.com/tntech-consulting/agent-identity-bridge/issues/new?template=bug_report.md).

## 3. Create your first passport

```bash
aib create --org yourcompany --agent my-bot --protocols mcp,a2a
```

## 4. Translate between formats

```bash
echo '{"name":"My Agent","skills":[{"id":"booking","name":"Booking"}]}' > card.json
aib translate --from a2a --to mcp --file card.json
```

## 5. Start the gateway

```bash
aib serve
# → http://localhost:8420/docs (Swagger UI)
```

## What's next?

- [Beta Tester Guide](https://github.com/tntech-consulting/agent-identity-bridge/blob/main/docs/beta-tester-guide.md) — 7 tests to run in ~1 hour
- [Error Codes](https://github.com/tntech-consulting/agent-identity-bridge/blob/main/ERROR_CODES.md) — All 33 error codes with fixes
- [Full README](https://github.com/tntech-consulting/agent-identity-bridge/blob/main/README.md) — Architecture, API, deployment

## Need help?

- [Report a bug](https://github.com/tntech-consulting/agent-identity-bridge/issues/new?template=bug_report.md)
- [Request a feature](https://github.com/tntech-consulting/agent-identity-bridge/issues/new?template=feature_request.md)
- Email: thomas.nirennold@live.fr
