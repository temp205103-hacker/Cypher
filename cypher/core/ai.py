"""Swappable AI explanation interface."""

from __future__ import annotations


def explain_risk(summary: str, redacted_snippet: str, offline: bool = True) -> str:
    context = f"\nDetected snippet (Before):\n  - {redacted_snippet[:160]}" if redacted_snippet else ""
    suggested_fix = (
        "\nSuggested fix (After):\n  + os.getenv('CONFIGURED_SECRET')  # Load secret securely from environment or secret manager"
        if any(w in summary.casefold() for w in ("key", "token", "password", "secret", "aws"))
        else "\nSuggested fix (After):\n  + # Use safe parameterization and avoid dynamic code execution"
    )
    if offline:
        return f"Review required: {summary}. Remove or replace the risky value and validate the change.{context}{suggested_fix}"
    return f"Cloud AI explanation unavailable in this module: {summary}"


def answer_question(question: str) -> str:
    lowered = question.casefold()
    if any(word in lowered for word in ("secret", "credential", "token", "key")):
        return "Keep credentials out of source control, rotate any exposed value, and store secrets in a managed secret store. Run `Cypher scan` to check local files."
    if any(word in lowered for word in ("email", "phone", "personal", "pii")):
        return "Avoid committing personal data. Use `Cypher redact <file>` to create a redacted copy without changing the original."
    if any(word in lowered for word in ("scan", "finding", "risk", "code")):
        return "Run `Cypher scan <path>` or `Cypher scan --staged`; inspect each result before changing code. Local pattern scans can miss issues."
    return "I can offer local-first guidance about secrets, personal data, and code scans. Do not paste credentials or sensitive data into questions."
