"""Command-line entry point for the secret scanner.

Usage:
    python cli.py file1.py file2.yaml          # scan given files
    python cli.py --staged                     # scan git-staged files
    python cli.py --staged --update-baseline    # accept current findings
"""

from __future__ import annotations

import argparse
import subprocess
import sys

from baseline import filter_baselined, load_baseline, write_baseline
from scan import Finding, is_probably_binary, scan_paths, scan_text

DEFAULT_BASELINE = ".secrets-baseline.json"


def get_staged_files() -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "-z", "--diff-filter=ACMR"],
        capture_output=True,
        text=True,
        check=True,
    )
    return [path for path in result.stdout.split("\0") if path]


def scan_staged(entropy_threshold: float) -> list[Finding]:
    findings = []
    for path in get_staged_files():
        data = subprocess.run(["git", "show", f":{path}"], capture_output=True, check=True).stdout
        if not is_probably_binary(data):
            findings.extend(scan_text(data.decode("utf-8", errors="replace"), path, entropy_threshold))
    return findings


def format_report(findings: list[Finding]) -> str:
    lines = [f"found {len(findings)} potential secret(s):", ""]
    for f in findings:
        lines.append(f"  {f.path}:{f.line_number} [{f.rule_id}] {f.description}")
        lines.append(f"      {f.snippet}")
    lines.append("")
    lines.append(
        "If any of these are false positives, review them and add an entry to "
        f"{DEFAULT_BASELINE} (or run with --update-baseline), or add an inline "
        "'# secret-scan: allow' comment on the line."
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan files for hardcoded secrets.")
    parser.add_argument("paths", nargs="*", help="files to scan")
    parser.add_argument(
        "--staged",
        action="store_true",
        help="scan git-staged files instead of an explicit path list",
    )
    parser.add_argument(
        "--baseline",
        default=DEFAULT_BASELINE,
        help=f"path to the baseline file (default: {DEFAULT_BASELINE})",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="write all current findings to the baseline instead of failing",
    )
    parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=4.3,
        help="minimum Shannon entropy (bits/char) to flag a string literal",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.staged and args.paths:
        print("error: pass either --staged or an explicit path list, not both", file=sys.stderr)
        return 2

    if not args.staged and not args.paths:
        print("no files to scan")
        return 0

    try:
        findings = (
            scan_staged(args.entropy_threshold)
            if args.staged
            else scan_paths(args.paths, entropy_threshold=args.entropy_threshold)
        )
    except subprocess.CalledProcessError:
        print("error: could not read the staged Git contents", file=sys.stderr)
        return 2

    if args.update_baseline:
        write_baseline(args.baseline, findings)
        print(f"wrote {len(findings)} finding(s) to {args.baseline}")
        return 0

    baseline = load_baseline(args.baseline)
    unbaselined = filter_baselined(findings, baseline)

    if not unbaselined:
        print(f"no unbaselined secrets found ({len(findings)} baselined)")
        return 0

    print(format_report(unbaselined), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
