"""Regex and entropy based secret detectors.

Pure functions only - no git or process calls here, so the detection
logic can be unit tested against plain strings.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

ALLOW_MARKER = "secret-scan: allow"

# (rule id, human description, compiled pattern)
RULES: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "aws-access-key-id",
        "AWS access key id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "aws-secret-key",
        "AWS secret access key assignment",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"),
    ),
    (
        "private-key-block",
        "PEM private key block",
        re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----"),
    ),
    (
        "generic-api-key",
        "generic API key/token/secret assignment",
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password|passwd)\s*[=:]\s*"
            r"['\"]?[A-Za-z0-9_\-/+=]{12,}['\"]?"
        ),
    ),
    (
        "slack-token",
        "Slack token",
        re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ),
]

ENTROPY_RULE_ID = "high-entropy-string"
_ENTROPY_CANDIDATE = re.compile(r"['\"][A-Za-z0-9+/_\-]{20,}['\"]")


@dataclass(frozen=True)
class Finding:
    rule_id: str
    description: str
    path: str
    line_number: int
    line_hash: str
    snippet: str


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.strip().encode("utf-8", errors="replace")).hexdigest()


def _redact(line: str) -> str:
    stripped = line.strip()
    if len(stripped) <= 16:
        return stripped
    return f"{stripped[:8]}...{stripped[-4:]}"


def scan_text(text: str, path: str, entropy_threshold: float = 4.3) -> list[Finding]:
    """Scan a block of text (one file's contents) for secrets.

    Lines carrying the ALLOW_MARKER comment are skipped entirely.
    """
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue

        for rule_id, description, pattern in RULES:
            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        description=description,
                        path=path,
                        line_number=lineno,
                        line_hash=_line_hash(line),
                        snippet=_redact(line),
                    )
                )

        for match in _ENTROPY_CANDIDATE.finditer(line):
            candidate = match.group(0)[1:-1]
            if _shannon_entropy(candidate) >= entropy_threshold:
                findings.append(
                    Finding(
                        rule_id=ENTROPY_RULE_ID,
                        description="high-entropy string literal",
                        path=path,
                        line_number=lineno,
                        line_hash=_line_hash(line),
                        snippet=_redact(line),
                    )
                )
                break  # one entropy finding per line is enough

    return findings


_BINARY_NULL = b"\x00"


def is_probably_binary(data: bytes) -> bool:
    return _BINARY_NULL in data[:8192]


def scan_file(path: str, entropy_threshold: float = 4.3) -> list[Finding]:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []

    if is_probably_binary(data):
        return []

    text = data.decode("utf-8", errors="replace")
    return scan_text(text, path, entropy_threshold=entropy_threshold)


def scan_paths(paths: list[str], entropy_threshold: float = 4.3) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(scan_file(path, entropy_threshold=entropy_threshold))
    return findings
