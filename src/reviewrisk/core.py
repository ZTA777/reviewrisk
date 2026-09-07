from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import re
from pathlib import PurePosixPath
from typing import Iterable

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Finding:
    severity: str
    rule: str
    file: str
    message: str
    evidence: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class ScanResult:
    findings: list[Finding]
    files_changed: int

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: SEVERITY_RANK[f.severity]).severity

    def to_dict(self) -> dict:
        counts = {name: 0 for name in SEVERITY_RANK}
        for finding in self.findings:
            counts[finding.severity] += 1
        return {
            "summary": {
                "files_changed": self.files_changed,
                "findings": len(self.findings),
                "highest_severity": self.highest_severity,
                "counts": counts,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
]

DANGEROUS_SHELL = [
    ("pipe-to-shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:sh|bash)\b", re.I)),
    ("decoded-shell", re.compile(r"\bbase64\b[^\n|]*(?:-d|--decode)[^\n|]*\|\s*(?:sh|bash)\b", re.I)),
    ("world-writable", re.compile(r"\bchmod\s+(?:-R\s+)?777\b", re.I)),
]

WORKFLOW_PERMISSION = re.compile(r"^\s*(contents|actions|checks|deployments|id-token|issues|packages|pages|pull-requests|security-events|statuses):\s*write\s*$", re.I)
WRITE_ALL = re.compile(r"^\s*permissions:\s*write-all\s*$", re.I)
LIFECYCLE_SCRIPT = re.compile(r'^[+].*"(?:preinstall|install|postinstall|prepare|prepublish|prepublishOnly)"\s*:', re.I)

SENSITIVE_PATHS: dict[str, tuple[str, str]] = {
    ".github/workflows/": ("high", "CI workflow changed"),
    ".github/actions/": ("high", "Local GitHub Action changed"),
    ".github/CODEOWNERS": ("high", "CODEOWNERS changed"),
    "CODEOWNERS": ("high", "CODEOWNERS changed"),
    ".npmrc": ("high", "npm configuration changed"),
    ".pypirc": ("high", "Python publishing configuration changed"),
    ".github/dependabot.yml": ("medium", "Dependency automation changed"),
}

DEPENDENCY_FILES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "requirements-dev.txt", "poetry.lock", "pyproject.toml",
    "Pipfile", "Pipfile.lock", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "composer.json", "composer.lock",
}

RELEASE_HINTS = ("release", "publish", "deploy")


def _norm_path(value: str) -> str:
    value = value.strip()
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return value


def _path_rule(path: str) -> tuple[str, str] | None:
    for prefix, value in SENSITIVE_PATHS.items():
        if path == prefix or path.startswith(prefix):
            return value
    name = PurePosixPath(path).name
    if name in DEPENDENCY_FILES:
        return ("medium", "Dependency manifest or lockfile changed")
    lower = path.lower()
    if any(hint in lower for hint in RELEASE_HINTS) and (lower.startswith(".github/") or lower.endswith((".sh", ".yml", ".yaml", ".toml"))):
        return ("medium", "Release/deployment automation changed")
    return None


def scan_diff(diff_text: str) -> ScanResult:
    findings: list[Finding] = []
    current_file = "<unknown>"
    changed_files: set[str] = set()
    seen_path_findings: set[tuple[str, str]] = set()

    lines = diff_text.splitlines()
    for line in lines:
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                current_file = _norm_path(parts[3])
            continue

        if line.startswith("+++ "):
            candidate = line[4:].strip()
            if candidate != "/dev/null":
                current_file = _norm_path(candidate)
                changed_files.add(current_file)
                path_finding = _path_rule(current_file)
                if path_finding:
                    severity, message = path_finding
                    key = (current_file, message)
                    if key not in seen_path_findings:
                        findings.append(Finding(severity, "sensitive-path", current_file, message))
                        seen_path_findings.add(key)
            continue

        if line.startswith("new file mode 100755"):
            findings.append(Finding("medium", "new-executable", current_file, "New executable file introduced", line.strip()))
            continue

        if not line.startswith("+") or line.startswith("+++"):
            continue

        added = line[1:]

        for rule, pattern in SECRET_PATTERNS:
            if pattern.search(added):
                findings.append(Finding("critical", rule, current_file, "Possible credential or private key added", _redact(added)))

        for rule, pattern in DANGEROUS_SHELL:
            if pattern.search(added):
                severity = "high" if rule != "world-writable" else "medium"
                message = {
                    "pipe-to-shell": "Remote content is piped directly to a shell",
                    "decoded-shell": "Decoded content is piped directly to a shell",
                    "world-writable": "World-writable permissions introduced",
                }[rule]
                findings.append(Finding(severity, rule, current_file, message, added.strip()[:180]))

        if WRITE_ALL.search(added):
            findings.append(Finding("high", "workflow-write-all", current_file, "GitHub Actions workflow requests write-all permissions", added.strip()))
        elif WORKFLOW_PERMISSION.search(added) and current_file.startswith(".github/workflows/"):
            findings.append(Finding("high", "workflow-write-permission", current_file, "GitHub Actions workflow requests a write permission", added.strip()))

        if LIFECYCLE_SCRIPT.search(line) and PurePosixPath(current_file).name == "package.json":
            findings.append(Finding("high", "package-lifecycle-script", current_file, "Package lifecycle script added or changed", added.strip()[:180]))

    return ScanResult(findings=_dedupe(findings), files_changed=len(changed_files))


def _redact(text: str) -> str:
    text = text.strip()
    if len(text) <= 18:
        return "[redacted]"
    return text[:8] + "…[redacted]…" + text[-4:]


def _dedupe(findings: Iterable[Finding]) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        key = (finding.severity, finding.rule, finding.file, finding.message)
        if key not in seen:
            seen.add(key)
            out.append(finding)
    return sorted(out, key=lambda f: (-SEVERITY_RANK[f.severity], f.file, f.rule))


def should_fail(result: ScanResult, threshold: str) -> bool:
    threshold_rank = SEVERITY_RANK[threshold]
    return any(SEVERITY_RANK[f.severity] >= threshold_rank for f in result.findings)
