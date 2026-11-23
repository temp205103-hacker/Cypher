"""Swappable AI explanation interface."""

from __future__ import annotations


def explain_risk(summary: str, redacted_snippet: str, offline: bool = True) -> str:
    if offline:
        context = f" The relevant redacted code is: {redacted_snippet[:160]}." if redacted_snippet else ""
        return f"Review required: {summary}. Remove or replace the risky value and validate the change.{context}"
    return f"Cloud AI explanation unavailable in this module: {summary}"


def answer_question(question: str) -> str:
    lowered = question.casefold()
    if any(word in lowered for word in ("secret", "credential", "token", "key")):
        return "Keep credentials out of source control, rotate any exposed value, and store secrets in a managed secret store. Run `GuardSnitch.ai scan` to check local files."
    if any(word in lowered for word in ("email", "phone", "personal", "pii")):
        return "Avoid committing personal data. Use `GuardSnitch.ai redact <file>` to create a redacted copy without changing the original."
    if any(word in lowered for word in ("scan", "finding", "risk", "code")):
        return "Run `GuardSnitch.ai scan <path>` or `GuardSnitch.ai scan --staged`; inspect each result before changing code. Local pattern scans can miss issues."
    return "I can offer local-first guidance about secrets, personal data, and code scans. Do not paste credentials or sensitive data into questions."
