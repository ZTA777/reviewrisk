# Contributing to reviewrisk

Thanks for helping make pull-request review safer and less tiring for maintainers.

## Before opening a pull request

1. Search existing issues and pull requests for related work.
2. Keep rules narrow and explainable; avoid heuristics that primarily guess a contributor's intent or identity.
3. Add or update tests for every detection change.
4. Do not add network calls to the default scan path without a strong design discussion.

## Development setup

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Pull-request expectations

- Explain the maintainer risk the change addresses.
- Include a minimal diff fixture that should trigger the rule.
- Include a nearby non-triggering case when false positives are plausible.
- Preserve redaction for anything that may be credential-like.
- Prefer standard-library solutions when practical.

Create feature branches from `main`. Conventional Commit-style messages such as `feat:`, `fix:`, `docs:`, and `test:` are welcome but not mandatory.

## Good first contributions

Documentation improvements, additional ecosystem fixtures, false-positive tests, CLI ergonomics, and rule documentation are all useful places to start.
