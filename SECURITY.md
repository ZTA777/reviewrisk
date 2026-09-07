# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository when available:

`https://github.com/ZTA777/reviewrisk/security/advisories/new`

Do not include real credentials, access tokens, or private source code in a report. Use synthetic examples.

## Threat model

reviewrisk parses untrusted diff text. It must not execute content from the diff, interpolate it into shell commands, or emit suspected secrets verbatim. Reports should remain safe to store in CI logs.
