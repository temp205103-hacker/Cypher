"""Static email parsing for link and header inconsistencies."""

from __future__ import annotations

from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[dict[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.casefold() == "a":
            self._href = next(
                (value for name, value in attrs if name.casefold() == "href" and value),
                None,
            )
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "a" and self._href is not None:
            self.links.append({"href": self._href, "text": " ".join(self._text).strip()})
            self._href = None
            self._text = []


def _address_domain(header_value: str | None) -> str:
    if not header_value:
        return ""
    parsed = getaddresses([header_value])
    if not parsed:
        return ""
    address = parsed[0][1]
    return address.rpartition("@")[2].casefold()


def parse_email(data: bytes) -> dict[str, Any]:
    """Extract email text, URLs, and static header indicators from .eml bytes."""
    message = BytesParser(policy=policy.default).parsebytes(data)
    text_parts: list[str] = []
    plain_parts: list[str] = []
    html_links: list[dict[str, str]] = []
    attachments: list[str] = []

    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            continue
        content_type = part.get_content_type().casefold()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
            body = content if isinstance(content, str) else str(content)
        except (LookupError, UnicodeError, TypeError):
            payload = part.get_payload(decode=True) or b""
            body = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        text_parts.append(body)
        if content_type == "text/plain":
            plain_parts.append(body)
        else:
            parser = _AnchorParser()
            parser.feed(body)
            html_links.extend(parser.links)

    body_text = "\n".join(text_parts)
    from_domain = _address_domain(message.get("From"))
    reply_to_domain = _address_domain(message.get("Reply-To"))
    evidence: list[str] = []
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        evidence.append("The Reply-To domain differs from the sender domain.")
    display_names = [name for name, _ in getaddresses([message.get("From", "")]) if name]
    if display_names and any(
        word in display_names[0].casefold()
        for word in ("bank", "support", "security", "account")
    ):
        evidence.append("The sender display name uses a security or financial authority term.")
    suspicious_attachments = [
        name
        for name in attachments
        if name.casefold().endswith(
            (".html", ".htm", ".lnk", ".js", ".vbs", ".ps1", ".hta", ".iso", ".img")
        )
    ]
    if suspicious_attachments:
        evidence.append(
            "The email contains potentially active attachment(s): "
            + ", ".join(sorted(suspicious_attachments))
        )
    authentication_results = str(message.get("Authentication-Results", ""))[:1000]
    return {
        "subject": str(message.get("Subject", ""))[:300],
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "authentication_results": authentication_results,
        "body_text": body_text,
        "plain_text": "\n".join(plain_parts),
        "html_links": html_links,
        "attachments": attachments,
        "evidence": evidence,
    }


def visible_domain_mismatch(link: dict[str, str]) -> bool:
    """Check whether an anchor's displayed URL host conflicts with its target."""
    href = link.get("href", "").strip()
    text = link.get("text", "").strip()
    if not href or not text:
        return False
    try:
        target = urlsplit(href if "://" in href else f"https://{href}").hostname
        visible = urlsplit(text if "://" in text else f"https://{text}").hostname
    except ValueError:
        return False
    return bool(target and visible and target.casefold() != visible.casefold())
