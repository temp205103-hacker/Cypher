"""Weighted, deterministic phishing URL scoring using local data only."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

from cypher.phish.lookalike import analyze_lookalikes, domain_matches
from cypher.phish import reputation
from cypher.phish.triage import explain
from cypher.phish.url_features import parse_url, url_signals


DATA_DIR = Path(__file__).resolve().parents[1] / "data"


@lru_cache(maxsize=1)
def _read_domains(filename: str) -> frozenset[str]:
    path = DATA_DIR / filename
    try:
        values = {
            line.strip().casefold().lstrip(".")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
    except OSError as exc:
        raise RuntimeError(f"Could not read local domain data {path}: {exc}") from exc
    return frozenset(values)


def _domain_in(host: str, entries: frozenset[str]) -> bool:
    return any(domain_matches(host, entry) for entry in entries)


def blocked_domains() -> list[str]:
    """Return local domains suitable for syncing to the browser extension."""
    bundled = _read_domains("phish_blocklist.txt")
    return sorted(bundled | reputation.user_blocked_domains())


def _verdict(score: int) -> str:
    if score >= 70:
        return "Phishing"
    if score >= 45:
        return "Suspicious"
    if score >= 25:
        return "Caution"
    return "Safe"


def analyze_url(url: str) -> dict[str, Any]:
    """Analyze a URL without DNS, HTTP, third-party, or browser access."""
    normalized, host, lexical = url_signals(url)
    trusted = _read_domains("trusted_domains.txt")
    blocklist = _read_domains("phish_blocklist.txt")
    user_allowed = reputation.user_allowed_domains()
    user_blocked = reputation.user_blocked_domains()

    if host and _domain_in(host, user_allowed):
        result: dict[str, Any] = {
            "url": normalized,
            "host": host,
            "verdict": "Safe",
            "risk_score": 0,
            "confidence": "High",
            "evidence": [],
            "groups": [],
            "source": "user-allowlist",
            "network_contacted": False,
        }
        result["explanation"] = explain(result)
        return result

    if host and _domain_in(host, user_blocked):
        evidence = [
            {
                "id": "user-blocklist",
                "category": "reputation",
                "weight": 100,
                "evidence": "The hostname matches your local phishing blocklist.",
            }
        ]
        result = {
            "url": normalized,
            "host": host,
            "verdict": "Phishing",
            "risk_score": 100,
            "confidence": "High",
            "evidence": evidence,
            "groups": ["reputation"],
            "source": "user-blocklist",
            "network_contacted": False,
        }
        result["explanation"] = explain(result)
        return result

    if host and _domain_in(host, blocklist):
        evidence = [
            {
                "id": "local-blocklist",
                "category": "reputation",
                "weight": 100,
                "evidence": "The hostname matches a locally maintained phishing blocklist.",
            }
        ]
        result: dict[str, Any] = {
            "url": normalized,
            "host": host,
            "verdict": "Phishing",
            "risk_score": 100,
            "confidence": "High",
            "evidence": evidence,
            "groups": ["reputation"],
            "source": "local-blocklist",
            "network_contacted": False,
        }
        result["explanation"] = explain(result)
        return result

    if host and _domain_in(host, trusted):
        result = {
            "url": normalized,
            "host": host,
            "verdict": "Safe",
            "risk_score": 0,
            "confidence": "High",
            "evidence": [],
            "groups": [],
            "source": "local-trusted-list",
            "network_contacted": False,
        }
        result["explanation"] = explain(result)
        return result

    evidence = [
        {
            "id": signal.id,
            "category": signal.category,
            "weight": signal.weight,
            "evidence": signal.evidence,
        }
        for signal in lexical
    ]
    evidence.extend(analyze_lookalikes(host))

    # Signals in the same family have a bounded total contribution. High verdicts
    # additionally require evidence from at least two independent families.
    family_totals: dict[str, int] = {}
    for item in evidence:
        family = str(item["category"])
        family_totals[family] = min(
            45, family_totals.get(family, 0) + int(item["weight"])
        )
    score = min(100, sum(family_totals.values()))
    if score >= 70 and len(family_totals) < 2:
        score = 69

    result = {
        "url": normalized,
        "host": host,
        "verdict": _verdict(score),
        "risk_score": score,
        "confidence": (
            "High" if len(family_totals) >= 3 or score == 0
            else "Medium" if len(family_totals) >= 2
            else "Low"
        ),
        "evidence": evidence,
        "groups": sorted(family_totals),
        "source": "local-heuristics",
        "network_contacted": False,
    }
    result["explanation"] = explain(result)
    return result
