"""Secret detectors."""

from __future__ import annotations

import re
from typing import Iterable


PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "generic_token": re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20}|xox[baprs]-[a-zA-Z0-9\-]+|sk-[a-zA-Z0-9]{20,})\b"),
    "database_url": re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s:@]+:[^\s:@]+@[^\s/:]+"),
    "password_assignment": re.compile(r"(?i)\b(?:password|passwd|secret)\s*=\s*['\"][^'\"]{4,}['\"]"),
}


def find_secrets(text: str) -> Iterable[tuple[str, str]]:
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            yield name, match.group(0)
