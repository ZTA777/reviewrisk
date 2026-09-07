# reviewrisk

**reviewrisk** is an offline-first CLI that scans pull-request diffs for changes that deserve extra maintainer attention.

It does **not** try to decide whether a contributor is trustworthy and it does **not** label a PR as malicious. It highlights high-impact surfaces so a maintainer can review them deliberately.

## Why this exists

Open-source maintainers routinely review changes that can alter the trust boundary of a project: CI workflows, release automation, package lifecycle scripts, dependency locks, CODEOWNERS, publishing credentials, and shell installers. Those changes can be buried inside otherwise ordinary pull requests.

`reviewrisk` turns those signals into a small, explainable report that works locally or in GitHub Actions. It has no runtime dependencies and does not send code to a third party.

## Current checks

- GitHub Actions workflow changes and newly requested write permissions
- `CODEOWNERS` and local GitHub Action changes
- Package lifecycle scripts such as `postinstall` and `prepare`
- Dependency manifests and lockfiles
- Release/deployment automation paths
- `curl | sh`, `wget | bash`, decoded shell pipelines, and `chmod 777`
- Newly introduced executable files
- Common credential shapes, with redacted evidence in reports

The rule set is intentionally small and explainable. False-positive resistance is more valuable than a giant opaque score.

## Installation

Requires Python 3.10+.

```bash
python -m pip install -e .
```

After publishing to PyPI, installation can become:

```bash
pip install reviewrisk
```

## Usage

Scan the current working-tree diff:

```bash
reviewrisk
```

Scan two revisions:

```bash
reviewrisk --git-diff origin/main HEAD
```

Scan a saved unified diff:

```bash
reviewrisk --diff-file examples/risky.diff
```

Machine-readable output:

```bash
reviewrisk --git-diff origin/main HEAD --format json
```

Markdown for CI summaries:

```bash
reviewrisk --git-diff origin/main HEAD --format markdown
```

By default the command exits with status 1 when it finds `high` or `critical` findings. Change the threshold with `--fail-on medium`, or use `--no-fail` while evaluating the tool.

## Example

```text
reviewrisk: 3 finding(s), highest=high, files=1

[HIGH    ] sensitive-path             .github/workflows/release.yml
           CI workflow changed
[HIGH    ] workflow-write-permission  .github/workflows/release.yml
           GitHub Actions workflow requests a write permission
[HIGH    ] pipe-to-shell              .github/workflows/release.yml
           Remote content is piped directly to a shell
```

## GitHub Actions

This repository includes `.github/workflows/reviewrisk.yml` as a working example. It checks the pull-request diff and writes a Markdown report to the GitHub Actions job summary.

For a production release, pin third-party Actions to immutable commit SHAs and document the update process.

## Design principles

1. **Offline first.** Source code and diffs stay on the machine running the scan.
2. **Explainable.** Every finding names the exact rule and reason.
3. **Human review remains authoritative.** A finding is a prompt to inspect context, not a verdict about a contributor.
4. **Safe output.** Suspected credentials are redacted rather than repeated into logs.
5. **Low dependency risk.** The scanner uses only the Python standard library at runtime.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
reviewrisk --diff-file examples/risky.diff --no-fail
```

## Roadmap

Good first issues for contributors:

- Parse git file-mode changes more precisely
- Add TOML configuration for per-repository allowlists and thresholds
- Add SARIF output for GitHub Code Scanning
- Add rule IDs with documentation pages and CWE references where appropriate
- Detect dangerous workflow triggers combined with untrusted PR data
- Detect changes to package publishing destinations and registry configuration
- Add fixtures for npm, PyPI, Cargo, Go, Ruby, and Composer projects
- Package and publish reproducible releases to PyPI

## Scope and limitations

`reviewrisk` is not a malware scanner, secret-management product, vulnerability database, or substitute for maintainer judgment. A safe-looking diff can still be harmful, and a flagged diff can be perfectly legitimate.

Please report bypasses, false positives, and risky patterns that can be detected without executing untrusted code.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Small rule additions should include a focused test fixture and an explanation of why the signal is useful to maintainers.

## Security

See [SECURITY.md](SECURITY.md). Please do not open a public issue for a vulnerability that could put users at immediate risk.

## License

MIT. See [LICENSE](LICENSE).
