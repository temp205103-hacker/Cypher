"""Evidence capture helpers with encryption-at-rest support."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from guardsnitch.config import appdata_dir


def evidence_key() -> bytes:
    stored = keyring.get_password("GuardSnitch.ai", "evidence-aes-key")
    if stored:
        return base64.urlsafe_b64decode(stored)
    key = AESGCM.generate_key(bit_length=256)
    keyring.set_password(
        "GuardSnitch.ai",
        "evidence-aes-key",
        base64.urlsafe_b64encode(key).decode("ascii"),
    )
    return key


def encrypt_evidence(data: bytes, name: str) -> Path:
    folder = appdata_dir() / "evidence"
    folder.mkdir(parents=True, exist_ok=True)
    nonce = os.urandom(12)
    encrypted = nonce + AESGCM(evidence_key()).encrypt(nonce, data, name.encode("utf-8"))
    target = folder / f"{name}.enc"
    target.write_bytes(encrypted)
    return target


def capture_screenshot() -> Path | None:
    try:
        import mss
        from PIL import Image
        import io

        with mss.mss() as capture:
            frame = capture.grab(capture.monitors[1])
        image = Image.frombytes("RGB", frame.size, frame.rgb)
        buffer = io.BytesIO()
        image.save(buffer, format="JPEG", quality=70)
        return encrypt_evidence(buffer.getvalue(), "theft-screenshot")
    except (ImportError, OSError):
        return None


def capture_webcam() -> Path | None:
    try:
        import cv2

        camera = cv2.VideoCapture(0)
        if not camera.isOpened():
            camera.release()
            return None
        ok, frame = camera.read()
        camera.release()
        if not ok:
            return None
        ok, encoded = cv2.imencode(".jpg", frame)
        if not ok:
            return None
        return encrypt_evidence(encoded.tobytes(), "theft-webcam")
    except (ImportError, OSError):
        return None
