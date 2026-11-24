"""Redaction helpers."""

from __future__ import annotations

import re

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----", re.DOTALL)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
PHONE = re.compile(r"\b(?:\+\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?){2}\d{4}\b")


def redact_text(text: str) -> str:
    text = PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
    text = AWS_ACCESS_KEY.sub("[REDACTED_AWS_ACCESS_KEY]", text)
    text = EMAIL.sub("[REDACTED_EMAIL]", text)
    text = PHONE.sub("[REDACTED_PHONE]", text)
    return text
