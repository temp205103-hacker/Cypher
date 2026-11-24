"""Optional, static QR and PDF text extraction with graceful fallbacks."""

from __future__ import annotations

from pathlib import Path
import re


_PDF_URL = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


def extract_qr_urls(path: Path) -> tuple[list[str], list[str]]:
    """Read QR data from supported local files; never open decoded destinations."""
    suffix = path.suffix.casefold()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
            from pypdf.errors import PdfReadError
        except ImportError:
            return [], ["PDF text/QR scan skipped: optional pypdf is not installed."]
        try:
            reader = PdfReader(str(path), strict=False)
            text = "\n".join(page.extract_text() or "" for page in reader.pages[:100])
        except (OSError, ValueError, PdfReadError) as exc:
            return [], [f"PDF scan could not read this file: {type(exc).__name__}."]
        return _PDF_URL.findall(text), [
            "PDF text was scanned; QR image decoding inside PDFs is unavailable."
        ]

    if suffix not in {".png", ".jpg", ".jpeg", ".bmp", ".webp", ".tif", ".tiff"}:
        return [], []
    try:
        import cv2
        import numpy as np
    except ImportError:
        return [], ["Image QR scan skipped: optional opencv-python is not installed."]
    try:
        image_bytes = path.read_bytes()
        image = cv2.imdecode(np.frombuffer(image_bytes, dtype=np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            return [], ["Image QR scan could not decode the file."]
        detector = cv2.QRCodeDetector()
        decoded: list[str] = []
        multi = getattr(detector, "detectAndDecodeMulti", None)
        if multi is not None:
            found, values, _, _ = multi(image)
            if found:
                decoded.extend(value for value in values if value)
        if not decoded:
            value, _, _ = detector.detectAndDecode(image)
            if value:
                decoded.append(value)
        return decoded, []
    except (OSError, ValueError, cv2.error) as exc:
        return [], [f"Image QR scan failed: {type(exc).__name__}."]
