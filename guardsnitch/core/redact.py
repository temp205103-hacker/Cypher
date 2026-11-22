"""Redaction helpers."""

from __future__ import annotations

import re

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----", re.DOTALL)


def redact_text(text: str) -> str:
    text = PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
    text = EMAIL.sub("[REDACTED_EMAIL]", text)
    return text
