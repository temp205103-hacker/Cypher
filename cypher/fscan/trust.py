"""Trusted paths and local hash allow/block lists."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from cypher.config import appdata_dir
from cypher.fscan.hashing import read_hash_set


EICAR_TEST_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
_REPOSITORY_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_PACKAGED_DATA_DIR = Path(__file__).resolve().parents[1] / "data"


def _data_dir() -> Path:
    if (_REPOSITORY_DATA_DIR / "blocklist.json").is_file():
        return _REPOSITORY_DATA_DIR
    return _PACKAGED_DATA_DIR


def _user_allowlist_path() -> Path:
    return appdata_dir() / "fscan-allowlist.json"


def _user_allowlist() -> dict[str, Any]:
    path = _user_allowlist_path()
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"sha256": [], "publishers": []}
    except OSError as exc:
        raise ValueError(f"Could not inspect local allowlist {path}: {exc}") from exc
    return _read_user_allowlist_cached(
        str(path.resolve()), stat.st_mtime_ns, stat.st_size
    )


def hash_reputation(sha256: str) -> str:
    local = _user_allowlist()
    if sha256.casefold() in set(local["sha256"]):
        return "user-allowlisted"
    data_dir = _data_dir()
    if sha256.casefold() in read_hash_set(data_dir / "allowlist.json"):
        return "allowlisted"
    if sha256.casefold() in read_hash_set(data_dir / "blocklist.json"):
        return "blocked"
    return "unknown"


@lru_cache(maxsize=8)
def _read_user_allowlist_cached(path: str, mtime_ns: int, size: int) -> dict[str, Any]:
    del mtime_ns, size
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read local allowlist {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Local allowlist {path} has an invalid format.")
    hashes = data.get("sha256", [])
    publishers = data.get("publishers", [])
    if not isinstance(hashes, list) or not all(
        isinstance(item, str) and len(item) == 64
        and all(character in "0123456789abcdefABCDEF" for character in item)
        for item in hashes
    ):
        raise ValueError(f"Local allowlist {path} must contain valid SHA-256 hashes.")
    if not isinstance(publishers, list) or not all(isinstance(item, str) for item in publishers):
        raise ValueError(f"Local allowlist {path} must contain a publishers array of strings.")
    return {
        "sha256": [item.casefold() for item in hashes],
        "publishers": publishers,
    }


def is_excluded_path(path: Path, project_root: Path | None = None) -> bool:
    try:
        candidate = path.resolve()
    except OSError:
        candidate = path.absolute()
    package_root = project_root or Path(__file__).resolve().parents[2]
    demo_root = package_root / "demo"
    for protected in (package_root, demo_root):
        try:
            candidate.relative_to(protected.resolve())
            return True
        except ValueError:
            pass

    if os.name == "nt":
        windows_root = Path(os.environ.get("WINDIR", r"C:\Windows"))
        try:
            candidate.relative_to(windows_root.resolve())
            return True
        except (ValueError, OSError):
            pass
    return False


def allow_hash(sha256: str) -> None:
    if len(sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in sha256):
        raise ValueError("Expected a 64-character SHA-256 hash.")
    path = _user_allowlist_path()
    data = _user_allowlist()
    values = {str(item).casefold() for item in data.get("sha256", [])}
    values.add(sha256.casefold())
    data["sha256"] = sorted(values)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(temporary, path)
    _read_user_allowlist_cached.cache_clear()
