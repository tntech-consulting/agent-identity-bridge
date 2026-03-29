# Contributing to AIB

## Quick start

```bash
git clone https://github.com/tntech-consulting/agent-identity-bridge.git
cd agent-identity-bridge
pip install -e ".[dev]"
python -m pytest tests/ -v
python -m aib.cli quickstart
```

## Development workflow

1. Fork the repo
2. Create a branch: `git checkout -b feature/my-feature`
3. Make changes
4. Run tests: `python -m pytest tests/ -v`
5. Run linter: `ruff check aib/`
6. Commit with a clear message
7. Push and open a PR

## Commit messages

Follow the pattern:
```
v2.X.Y: Short description

module.py (NEW/MODIFIED):
  What changed and why
```

## Tests

Every new feature needs tests. Target: no PR merges with fewer tests than before.

```bash
# Run all tests
python -m pytest tests/ -v

# Run a single test file
python -m pytest tests/test_passport.py -v

# Run with coverage (if installed)
python -m pytest tests/ --cov=aib --cov-report=term-missing
```

## Code style

- Python 3.11+
- Ruff for linting (`ruff check aib/`)
- Type hints encouraged but not enforced
- Docstrings on public classes and functions
- No external dependencies unless absolutely necessary

## Project structure

```
aib/               # Main package (v2.15.1)
  passport.py      # Passport creation, signing, verification
  translator.py    # Cross-protocol format conversion (6 paths)
  policy_engine.py # 12 rule types, deliverable gates
  lifecycle.py     # Delegation chains, tiers, ephemeral
  did.py           # W3C DID v1.1 (did:web + did:key)
  integrations.py  # LangChain, CrewAI, OpenAI Agents SDK
  cloud.py         # AIB Cloud SDK (managed SaaS client)
  cli.py           # Command line interface
  ...
tests/             # 1,054 tests
cloud/landing/     # Site (12 pages, EN/FR)
examples/          # quickstart.py (8 steps)
```

## Reporting bugs

Use the [bug report template](https://github.com/tntech-consulting/agent-identity-bridge/issues/new?template=bug_report.md).

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. **Do not open public issues for security vulnerabilities.**
