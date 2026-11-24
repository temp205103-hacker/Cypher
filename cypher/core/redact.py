"""Redaction helpers."""

from __future__ import annotations

import re

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PRIVATE_KEY = re.compile(r"-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----", re.DOTALL)
AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
PHONE = re.compile(r"\b(?:\+\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?){2}\d{4}\b")
GENERIC_TOKEN = re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20}|xox[baprs]-[a-zA-Z0-9\-]+|sk-[a-zA-Z0-9]{20,})\b")
CREDIT_CARD = re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PASSWORD = re.compile(r"(?i)\b(?:password|passwd|secret)\s*=\s*(['\"])[^'\"]{4,}\1")


def redact_text(text: str) -> str:
    text = PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY]", text)
    text = AWS_ACCESS_KEY.sub("[REDACTED_AWS_ACCESS_KEY]", text)
    text = GENERIC_TOKEN.sub("[REDACTED_TOKEN]", text)
    text = CREDIT_CARD.sub("[REDACTED_CARD]", text)
    text = SSN.sub("[REDACTED_SSN]", text)
    text = PASSWORD.sub(r"password=\1[REDACTED_PASSWORD]\1", text)
    text = EMAIL.sub("[REDACTED_EMAIL]", text)
    text = PHONE.sub("[REDACTED_PHONE]", text)
    return text
