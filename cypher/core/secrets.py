"""Secret detectors."""

from __future__ import annotations

import re
from typing import Iterable


PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
}


def find_secrets(text: str) -> Iterable[tuple[str, str]]:
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            yield name, match.group(0)
