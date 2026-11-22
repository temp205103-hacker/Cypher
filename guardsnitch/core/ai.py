"""Swappable AI explanation interface."""

from __future__ import annotations


def explain_risk(summary: str, redacted_snippet: str, offline: bool = True) -> str:
    del redacted_snippet
    if offline:
        return f"Review required: {summary}. Remove or replace the risky value and validate the change."
    return f"Cloud AI explanation unavailable in this module: {summary}"
