"""Baseline file handling - suppress known/accepted findings.

The baseline is a JSON file listing (path, rule_id, line_hash) triples
that have been reviewed and accepted. It's keyed on a hash of the
line's content, not the line number, so reformatting or moving code
doesn't silently invalidate an entry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from scan import Finding


@dataclass(frozen=True)
class BaselineEntry:
    path: str
    rule_id: str
    line_hash: str


def load_baseline(baseline_path: str) -> set[BaselineEntry]:
    try:
        with open(baseline_path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return set()

    entries = set()
    for item in raw.get("allowed", []):
        entries.add(
            BaselineEntry(
                path=item["path"],
                rule_id=item["rule_id"],
                line_hash=item["line_hash"],
            )
        )
    return entries


def is_baselined(finding: Finding, baseline: set[BaselineEntry]) -> bool:
    entry = BaselineEntry(path=finding.path, rule_id=finding.rule_id, line_hash=finding.line_hash)
    return entry in baseline


def filter_baselined(findings: list[Finding], baseline: set[BaselineEntry]) -> list[Finding]:
    return [f for f in findings if not is_baselined(f, baseline)]


def write_baseline(baseline_path: str, findings: list[Finding]) -> None:
    """Write every given finding into a fresh baseline file.

    Used to accept the current state of a repo as a starting point.
    """
    payload = {
        "allowed": [{"path": f.path, "rule_id": f.rule_id, "line_hash": f.line_hash} for f in findings]
    }
    with open(baseline_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")
