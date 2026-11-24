"""Privacy-preserving, offline explanation templates for phishing findings."""

from __future__ import annotations

from typing import Any


def explain(result: dict[str, Any]) -> str:
    """Explain a URL score without sending its contents to an external service."""
    verdict = str(result.get("verdict", "Unknown"))
    evidence = result.get("evidence", [])
    details = [
        str(item.get("evidence", ""))
        for item in evidence
        if isinstance(item, dict) and item.get("evidence")
    ]
    if verdict == "Safe":
        return (
            "No strong phishing indicators were found in the URL itself. "
            "This local check does not prove that the destination is safe."
        )
    if not details:
        return "The URL matched a locally maintained phishing blocklist entry."
    return " ".join(details[:3])
