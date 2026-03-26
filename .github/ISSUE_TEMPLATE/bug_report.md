---
name: Bug Report
about: Something isn't working as expected
title: "[BUG] "
labels: bug
assignees: ''
---

## What happened?

A clear description of what went wrong.

## Steps to reproduce

```python
# Paste the code that triggered the bug
from aib.passport import PassportService
svc = PassportService(secret_key="test")
# ...
```

## Expected behavior

What should have happened instead.

## Error output

```
Paste the full error message or traceback here.
If available, include the AIB error code (e.g. AIB-301).
```

## Environment

- **AIB version**: (run `pip show agent-identity-bridge`)
- **Python version**: (run `python --version`)
- **OS**: (e.g. Ubuntu 24.04, macOS 15, Windows 11)
- **Install method**: pip / Docker / git clone

## Diagnostic output (optional)

```python
from aib.diagnostics import diagnose_error
# If you caught the exception:
result = diagnose_error(your_exception)
print(result.to_dict())
```

## Additional context

Any other info that might help (screenshots, logs, config).
