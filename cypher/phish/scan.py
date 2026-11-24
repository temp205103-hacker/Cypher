"""Local extraction of links from text, files, and email messages."""

from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from typing import Any

from cypher.phish.analyzer import analyze_url
from cypher.phish.email_parser import parse_email, visible_domain_mismatch
from cypher.phish.qr import extract_qr_urls


MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES = 1000
URL_PATTERN = re.compile(
    r"(?i)(?:https?://|www\.)[^\s<>\"']+|"
    r"(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+"
    r"(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})(?::\d+)?(?:/[^\s<>\"']*)?"
)
TRAILING_PUNCTUATION = ".,;:!?)]}\"'"


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name.casefold() in {"href", "src", "action"} and value:
                if value.casefold().startswith(("http://", "https://", "www.")):
                    self.links.append(value.strip())


def extract_urls(text: str) -> list[str]:
    """Find unique web links in text and common HTML attributes."""
    candidates = [match.group(0) for match in URL_PATTERN.finditer(text)]
    parser = _LinkParser()
    try:
        parser.feed(text)
    except (ValueError, AssertionError):
        pass
    candidates.extend(parser.links)
    result: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        value = candidate.rstrip(TRAILING_PUNCTUATION)
        if value.casefold().startswith("www."):
            value = "https://" + value
        key = value.casefold()
        if value and key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _analyze_links(links: list[str], source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for link in links:
        result = analyze_url(link)
        findings.append({"source": source, **result})
    return findings


def scan_text(text: str, source: str = "stdin") -> dict[str, Any]:
    """Extract and analyze URLs from caller-provided text."""
    links = extract_urls(text)
    return {
        "files_scanned": 0,
        "links_found": len(links),
        "findings": _analyze_links(links, source),
        "warnings": [],
        "message_evidence": [],
    }


def _read_file(path: Path) -> tuple[str, list[str], list[str], list[str]]:
    warnings: list[str] = []
    message_evidence: list[str] = []
    if path.stat().st_size > MAX_FILE_BYTES:
        return "", [f"Skipped file larger than {MAX_FILE_BYTES} bytes: {path}"], [], []
    data = path.read_bytes()
    if path.suffix.casefold() == ".eml":
        message = parse_email(data)
        body = str(message["plain_text"])
        message_evidence.extend(str(item) for item in message["evidence"])
        email_links = [
            str(link["href"])
            for link in message["html_links"]
            if isinstance(link, dict) and link.get("href")
        ]
        for link in message["html_links"]:
            if visible_domain_mismatch(link):
                message_evidence.append(
                    "Email link text and destination domains differ: "
                    f"{link['text'][:120]} -> {link['href'][:200]}"
                )
        return body, warnings, message_evidence, email_links
    if path.suffix.casefold() == ".msg":
        return "", ["Outlook .msg parsing is unavailable; export it as .eml for scanning."], [], []
    if path.suffix.casefold() == ".lnk":
        return "", ["Shortcut contents were not executed or resolved; inspect its target manually."], [], []
    try:
        return data.decode("utf-8-sig"), warnings, message_evidence, []
    except UnicodeError:
        return data.decode("utf-8", errors="replace"), warnings, message_evidence, []


def scan_path(path: str | Path) -> dict[str, Any]:
    """Scan supported local text, email, image, and PDF inputs without executing them."""
    target = Path(path).expanduser()
    if not target.exists():
        raise FileNotFoundError(f"Path does not exist: {target}")
    if target.is_symlink():
        raise ValueError("Symbolic links are not followed during phishing scans.")
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = []
        for child in target.rglob("*"):
            if child.is_symlink():
                continue
            if child.is_file():
                files.append(child)
                if len(files) >= MAX_FILES:
                    break
    else:
        raise ValueError("The scan path is not a regular file or directory.")

    findings: list[dict[str, Any]] = []
    warnings: list[str] = []
    message_evidence: list[str] = []
    files_scanned = 0
    supported = {
        ".txt", ".md", ".html", ".htm", ".csv", ".log", ".eml", ".msg",
        ".json", ".xml", ".yaml", ".yml", ".ps1", ".bat", ".cmd", ".js",
        ".vbs", ".hta", ".pdf", ".png", ".jpg", ".jpeg", ".bmp", ".webp",
        ".tif", ".tiff", ".lnk",
    }
    for file_path in files:
        if file_path.suffix.casefold() not in supported:
            continue
        if file_path.is_symlink():
            continue
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                warnings.append(
                    f"Skipped file larger than {MAX_FILE_BYTES} bytes: {file_path}"
                )
                continue
            if file_path.suffix.casefold() in {
                ".pdf", ".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"
            }:
                qr_urls, qr_warnings = extract_qr_urls(file_path)
                warnings.extend(f"{file_path}: {item}" for item in qr_warnings)
                findings.extend(_analyze_links(qr_urls, str(file_path)))
                files_scanned += 1
                continue
            text, file_warnings, file_evidence, explicit_links = _read_file(file_path)
            warnings.extend(file_warnings)
            message_evidence.extend(
                f"{file_path}: {item}" for item in file_evidence
            )
            links = extract_urls(text) + explicit_links
            findings.extend(_analyze_links(list(dict.fromkeys(links)), str(file_path)))
            files_scanned += 1
        except (OSError, ValueError, RuntimeError) as exc:
            warnings.append(f"{file_path}: {exc}")

    if len(files) >= MAX_FILES:
        warnings.append(f"Scan stopped at the {MAX_FILES}-file safety limit.")
    return {
        "files_scanned": files_scanned,
        "links_found": len(findings),
        "findings": findings,
        "warnings": warnings,
        "message_evidence": message_evidence,
    }


def read_stdin() -> str:
    """Read pasted text from stdin for `phish scan -`."""
    return sys.stdin.read(MAX_FILE_BYTES + 1)
