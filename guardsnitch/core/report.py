"""Report serialization helpers."""

from __future__ import annotations

import json
from typing import Iterable


def to_json(findings: Iterable[dict[str, object]]) -> str:
    return json.dumps(list(findings), indent=2)
