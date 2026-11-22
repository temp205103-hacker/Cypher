"""Country lookup helpers for VPN server selection."""

from __future__ import annotations

import difflib
import re
import unicodedata
from dataclasses import dataclass


@dataclass(frozen=True)
class Country:
    code: str
    name: str
    flag: str


_COUNTRIES = (
    ("AU", "Australia", ("australia",)),
    ("AT", "Austria", ("osterreich",)),
    ("BE", "Belgium", ("belgie",)),
    ("BR", "Brazil", ("brasil",)),
    ("CA", "Canada", ()),
    ("DK", "Denmark", ("danmark",)),
    ("FI", "Finland", ("suomi",)),
    ("FR", "France", ("france",)),
    ("DE", "Germany", ("deutschland", "allemagne")),
    ("IN", "India", ("bharat",)),
    ("IE", "Ireland", ("eire",)),
    ("IT", "Italy", ("italia",)),
    ("JP", "Japan", ("nippon", "nihon")),
    ("MX", "Mexico", ("mexico",)),
    ("NL", "Netherlands", ("holland", "nederland")),
    ("NZ", "New Zealand", ("aotearoa",)),
    ("NO", "Norway", ("norge",)),
    ("PL", "Poland", ("polska",)),
    ("PT", "Portugal", ()),
    ("SG", "Singapore", ()),
    ("ES", "Spain", ("espana",)),
    ("SE", "Sweden", ("sverige",)),
    ("CH", "Switzerland", ("schweiz", "suisse", "svizzera")),
    ("GB", "United Kingdom", ("uk", "great britain", "britain")),
    ("US", "United States", ("usa", "united states of america", "america")),
)


def _normalize(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value.casefold())
    ascii_text = decomposed.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", " ", ascii_text).strip()


def _flag(code: str) -> str:
    return "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in code)


_COUNTRY_OBJECTS = tuple(
    Country(code=code, name=name, flag=_flag(code))
    for code, name, _aliases in _COUNTRIES
)
_BY_CODE = {country.code: country for country in _COUNTRY_OBJECTS}
_LOOKUP: dict[str, Country] = {}
for (code, _name, aliases), country in zip(_COUNTRIES, _COUNTRY_OBJECTS):
    for label in (code, country.name, *aliases):
        _LOOKUP[_normalize(label)] = country


def resolve_country(value: str) -> Country:
    """Resolve an ISO code, country name, or close spelling."""
    normalized = _normalize(value)
    if not normalized:
        raise ValueError("Enter a country name or ISO code.")
    exact = _LOOKUP.get(normalized)
    if exact:
        return exact

    match = difflib.get_close_matches(normalized, tuple(_LOOKUP), n=1, cutoff=0.72)
    if match:
        return _LOOKUP[match[0]]
    raise ValueError(
        f"Unknown country {value!r}. Try an ISO code such as DE, US, or JP."
    )


def available_countries() -> list[Country]:
    """Return countries supported by the current mock provider."""
    return sorted(_BY_CODE.values(), key=lambda country: country.name)
