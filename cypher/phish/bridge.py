"""Local browser-extension authentication helpers."""

from __future__ import annotations

import secrets

from cypher.config import CypherConfig


def extension_token() -> str:
    """Return a persistent random token used only for loopback extension APIs."""
    config = CypherConfig.load()
    if not config.dashboard_token or len(config.dashboard_token) < 32:
        config.dashboard_token = secrets.token_urlsafe(32)
        config.save()
    return config.dashboard_token
