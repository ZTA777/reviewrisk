from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .core import SEVERITY_RANK, scan_diff, should_fail


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reviewrisk",
        description="Scan a unified git diff for maintainer-sensitive changes.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--diff-file", type=Path, help="Read unified diff from a file")
    source.add_argument("--git-diff", nargs="*", metavar="REV", help="Run git diff with optional revisions, e.g. --git-diff origin/main HEAD")
    parser.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_RANK), default="high", help="Exit 1 when findings at or above this level exist")
    parser.add_argument("--no-fail", action="store_true", help="Always exit 0")
    parser.add_argument("--version", action="version", version="reviewrisk 0.1.0")
    return parser


def _read_diff(args: argparse.Namespace) -> str:
    if args.diff_file:
        return args.diff_file.read_text(encoding="utf-8")
    if args.git_diff is not None:
        command = ["git", "diff", "--no-ext-diff", "--unified=3", *args.git_diff]
        proc = subprocess.run(command, check=False, capture_output=True, text=True)
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(proc.returncode)
        return proc.stdout
    if sys.stdin.isatty():
        proc = subprocess.run(["git", "diff", "--no-ext-diff", "--unified=3"], check=False, capture_output=True, text=True)
        if proc.returncode != 0:
            print("No diff provided. Pipe a unified diff, use --diff-file, or run inside a git repository.", file=sys.stderr)
            raise SystemExit(2)
        return proc.stdout
    return sys.stdin.read()


def _render_text(result) -> str:
    if not result.findings:
        return f"reviewrisk: no findings across {result.files_changed} changed file(s)."
    lines = [f"reviewrisk: {len(result.findings)} finding(s), highest={result.highest_severity}, files={result.files_changed}", ""]
    for f in result.findings:
        lines.append(f"[{f.severity.upper():8}] {f.rule:26} {f.file}")
        lines.append(f"           {f.message}")
        if f.evidence:
            lines.append(f"           evidence: {f.evidence}")
    return "\n".join(lines)


def _render_markdown(result) -> str:
    lines = ["## reviewrisk report", "", f"**Highest severity:** `{result.highest_severity}`  ", f"**Changed files:** {result.files_changed}  ", f"**Findings:** {len(result.findings)}", ""]
    if not result.findings:
        lines.append("No maintainer-sensitive changes detected by the current rule set.")
        return "\n".join(lines)
    lines.extend(["| Severity | Rule | File | Why it matters |", "|---|---|---|---|"])
    for f in result.findings:
        safe_msg = f.message.replace("|", "\\|")
        safe_file = f.file.replace("|", "\\|")
        lines.append(f"| **{f.severity}** | `{f.rule}` | `{safe_file}` | {safe_msg} |")
    lines.extend(["", "> This is a review aid, not a vulnerability verdict. Confirm findings in context before blocking a contribution."])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    result = scan_diff(_read_diff(args))

    if args.format == "json":
        print(result.to_json())
    elif args.format == "markdown":
        print(_render_markdown(result))
    else:
        print(_render_text(result))

    if args.no_fail:
        return 0
    return 1 if should_fail(result, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
