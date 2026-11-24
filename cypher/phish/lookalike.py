"""Brand-domain lookalike checks with no DNS or web requests."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
import unicodedata
from typing import Any


DATA_DIR = Path(__file__).resolve().parents[1] / "data"
MULTI_LABEL_SUFFIXES = {
    "ac.in",
    "co.in",
    "co.jp",
    "co.nz",
    "co.uk",
    "com.au",
    "com.br",
    "com.in",
    "com.mx",
    "com.sg",
    "com.za",
    "gov.in",
    "net.in",
    "org.in",
}
SUSPICIOUS_BRAND_SUFFIXES = {
    "account",
    "billing",
    "help",
    "login",
    "secure",
    "service",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
}


@lru_cache(maxsize=1)
def load_brands() -> dict[str, dict[str, Any]]:
    """Load the bundled brand/domain reference set."""
    path = DATA_DIR / "brands.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not load phishing brand data: {exc}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("The bundled phishing brand data is invalid.")
    return value


def registrable_domain(host: str) -> str:
    """Approximate the registrable domain without requiring tldextract."""
    labels = host.casefold().strip(".").split(".")
    if len(labels) < 2:
        return host.casefold()
    suffix2 = ".".join(labels[-2:])
    take = 3 if suffix2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3 else 2
    return ".".join(labels[-take:])


def domain_matches(host: str, domain: str) -> bool:
    """Match a domain and its subdomains on label boundaries."""
    host = host.casefold().strip(".")
    domain = domain.casefold().strip(".")
    return host == domain or host.endswith("." + domain)


def edit_distance(left: str, right: str, limit: int = 2) -> int:
    """Compute bounded Levenshtein distance for short DNS labels."""
    if left == right:
        return 0
    if abs(len(left) - len(right)) > limit:
        return limit + 1
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, 1):
        current = [row]
        for column, right_char in enumerate(right, 1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[column] + 1,
                    previous[column - 1] + (left_char != right_char),
                )
            )
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def _scripts(value: str) -> set[str]:
    scripts = set()
    for char in value:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "HEBREW", "ARABIC"):
            if script in name:
                scripts.add(script)
                break
    return scripts


def analyze_lookalikes(host: str) -> list[dict[str, object]]:
    """Return lookalike evidence for a hostname."""
    if not host:
        return []
    brands = load_brands()
    domain = registrable_domain(host)
    base_label = domain.split(".")[0]
    host_labels = host.casefold().split(".")
    signals: list[dict[str, object]] = []

    def add(signal_id: str, weight: int, evidence: str) -> None:
        signals.append(
            {
                "id": signal_id,
                "category": "brand-lookalike",
                "weight": weight,
                "evidence": evidence,
            }
        )

    ascii_host = host
    try:
        ascii_host = host.encode("idna").decode("ascii").casefold()
    except UnicodeError:
        pass
    if any(label.startswith("xn--") for label in ascii_host.split(".")):
        add(
            "punycode-lookalike",
            18,
            "The hostname includes a punycode label that can conceal similar-looking characters.",
        )
    scripts = _scripts(host)
    if len(scripts) > 1:
        add(
            "mixed-script-host",
            22,
            "The hostname mixes writing systems, a common way to imitate a brand.",
        )

    for brand_name, item in brands.items():
        if not isinstance(item, dict):
            continue
        brand_domains = item.get("domains", [])
        if not isinstance(brand_domains, list):
            continue
        brand_labels = {
            registrable_domain(str(brand_domain)).split(".")[0]
            for brand_domain in brand_domains
            if isinstance(brand_domain, str)
        }
        display = str(item.get("display", brand_name))
        if base_label in brand_labels:
            continue

        for brand_label in sorted(brand_labels):
            tokens = base_label.split("-")
            if len(brand_label) >= 5 and (
                edit_distance(base_label, brand_label, 1) == 1
                or any(edit_distance(token, brand_label, 1) == 1 for token in tokens)
            ):
                add(
                    "brand-typosquat",
                    38,
                    f"The registered domain resembles {display}, but is not one of its listed domains.",
                )
                break
            if (
                brand_label in tokens
                and len(tokens) > 1
                and any(token in SUSPICIOUS_BRAND_SUFFIXES for token in tokens)
            ):
                add(
                    "brand-combosquat",
                    36,
                    f"The registered domain combines {display} with account or security wording.",
                )
                break

        if any(
            label in brand_labels
            for label in host_labels[:-2]
        ):
            add(
                "brand-in-subdomain",
                18,
                f"The hostname places {display} in a subdomain, not in the registered domain.",
            )

        if brand_name in host_labels[:-1] and base_label not in brand_labels:
            add(
                "brand-host-label",
                16,
                f"The hostname uses {display}'s name outside its registered domain.",
            )

    # Keep one finding per family so repeated brand matches cannot inflate scores.
    unique: dict[str, dict[str, object]] = {}
    for signal in signals:
        unique.setdefault(str(signal["id"]), signal)
    return list(unique.values())
