"""Download and statically inspect a script without executing it."""

from __future__ import annotations

import ipaddress
import socket
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlparse

from guardsnitch.core.scanner import MAX_FILE_BYTES, scan_text


class SafeRunError(RuntimeError):
    """Expected, user-facing safe inspection failure."""


def validate_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    try:
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
        }
    except (OSError, ValueError):
        return False
    return bool(addresses) and all(address.is_global for address in addresses)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def inspect_url(url: str) -> dict[str, object]:
    if not validate_url(url):
        raise SafeRunError("Enter a public HTTP or HTTPS URL; local and private network targets are refused.")
    request = Request(url, headers={"User-Agent": "GuardSnitch.ai safe-run inspector"})
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=15) as response:
            data = response.read(MAX_FILE_BYTES + 1)
            content_type = response.headers.get("Content-Type", "")
    except (HTTPError, URLError, OSError) as exc:
        raise SafeRunError(f"Could not inspect URL: {exc}") from exc
    if len(data) > MAX_FILE_BYTES:
        raise SafeRunError(f"Download exceeds the {MAX_FILE_BYTES}-byte inspection limit.")
    if b"\0" in data:
        return {
            "url": url,
            "content_type": content_type,
            "bytes": len(data),
            "status": "not-text",
            "findings": [],
            "executed": False,
        }
    text = data.decode("utf-8", errors="replace")
    findings = scan_text(text, url)
    return {
        "url": url,
        "content_type": content_type,
        "bytes": len(data),
        "status": "suspicious" if findings else "no-patterns-found",
        "findings": findings,
        "executed": False,
        "warning": "Static inspection cannot establish that a download is safe. The file was not executed.",
    }
