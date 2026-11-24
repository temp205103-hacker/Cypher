"""Personal information detectors."""

from __future__ import annotations

import re
from typing import Iterable

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE = re.compile(r"\b(?:\+\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?){2}\d{4}\b")


def find_pii(text: str) -> Iterable[tuple[str, str]]:
    for name, pattern in (("email", EMAIL), ("phone", PHONE)):
        for match in pattern.finditer(text):
            yield name, match.group(0)
