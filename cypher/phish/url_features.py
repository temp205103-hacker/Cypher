"""Deterministic lexical URL checks; this module never performs network I/O."""

from __future__ import annotations

import ipaddress
import re
from typing import NamedTuple
from urllib.parse import SplitResult, urlsplit


class UrlSignal(NamedTuple):
    id: str
    category: str
    weight: int
    evidence: str


SUSPICIOUS_TERMS = re.compile(
    r"(?:account|billing|confirm|login|password|recover|secure|signin|update|verify|wallet)",
    re.IGNORECASE,
)
SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "t.co",
    "tinyurl.com",
}


def parse_url(value: str) -> tuple[SplitResult, str]:
    """Parse a URL or bare hostname without contacting its destination."""
    if not isinstance(value, str) or not value.strip() or len(value) > 8192:
        raise ValueError("Enter a non-empty URL shorter than 8192 characters.")
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate or candidate.lower().startswith(
        ("javascript:", "data:")
    ) else f"//{candidate}")
    try:
        host = (parsed.hostname or "").rstrip(".").casefold()
        parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid hostname or port.") from exc
    return parsed, host


def url_signals(value: str) -> tuple[str, str, list[UrlSignal]]:
    """Return parsed URL, hostname, and stable lexical evidence."""
    parsed, host = parse_url(value)
    original = value.strip()
    scheme = parsed.scheme.casefold()
    signals: list[UrlSignal] = []

    def add(signal_id: str, category: str, weight: int, evidence: str) -> None:
        signals.append(UrlSignal(signal_id, category, weight, evidence))

    if scheme in {"javascript", "data"}:
        add(
            "active-content-scheme",
            "scheme",
            55,
            f"The link uses a {scheme}: URI instead of a normal web address.",
        )
        return original, "", signals

    effective_scheme = scheme if "://" in original else ""
    if effective_scheme and effective_scheme not in {"http", "https"}:
        add("non-web-scheme", "scheme", 45, "The link does not use HTTP or HTTPS.")

    if not host:
        add("missing-host", "structure", 30, "The URL has no recognizable hostname.")
        return original, host, signals

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None

    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        add(
            "userinfo-trick",
            "url-credentials",
            28,
            "The URL contains user-info before @, which can disguise the actual host.",
        )

    if address is not None:
        add(
            "ip-host",
            "host",
            22,
            "The link uses a numeric IP address instead of a recognizable domain.",
        )
    else:
        labels = host.split(".")
        if len(labels) >= 5:
            add(
                "deep-subdomains",
                "host",
                12,
                "The hostname has an unusually large number of subdomains.",
            )
        try:
            ascii_host = host.encode("idna").decode("ascii").casefold()
        except UnicodeError:
            ascii_host = host
        if any(label.startswith("xn--") for label in ascii_host.split(".")):
            add(
                "punycode-host",
                "internationalized-host",
                18,
                "The hostname contains an encoded internationalized domain label.",
            )

    if effective_scheme == "http":
        add("unencrypted-http", "transport", 5, "The link uses unencrypted HTTP.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The URL contains an invalid port.") from exc
    if port is not None and port not in {80, 443}:
        add(
            "unusual-port",
            "network",
            12,
            f"The link uses the uncommon port {port}.",
        )

    if len(original) > 200:
        add(
            "very-long-url",
            "structure",
            10,
            "The URL is unusually long and may be obscuring its destination.",
        )
    elif len(original) > 100:
        add("long-url", "structure", 5, "The URL is longer than typical web links.")

    if "%" in parsed.netloc or re.search(r"%(?:2f|5c|40|2e)", original, re.IGNORECASE):
        add(
            "encoded-url-components",
            "encoding",
            10,
            "Percent-encoding is used in the host or to obscure URL separators.",
        )

    if SUSPICIOUS_TERMS.search(f"{host}{parsed.path}{parsed.query}"):
        add(
            "account-action-terms",
            "content-terms",
            8,
            "The hostname or URL path contains account, sign-in, or verification language.",
        )

    if host in SHORTENERS:
        add(
            "shortener",
            "destination",
            16,
            "A URL-shortening service hides the final destination.",
        )

    return original, host, signals
