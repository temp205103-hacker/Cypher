"""Chunked file hashing and a local incremental scan cache."""

from __future__ import annotations

import hashlib
import atexit
from functools import lru_cache
import json
import os
from pathlib import Path
import sqlite3
from threading import RLock

from guardsnitch.config import appdata_dir


CHUNK_SIZE = 1024 * 1024
_CACHE_LOCK = RLock()
_CONNECTIONS: dict[str, sqlite3.Connection | None] = {}
_PENDING_COMMITS = 0


def sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def _stable_sha256(path: Path, before: os.stat_result) -> str:
    digest = sha256_file(path)
    after = path.stat()
    if (
        before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_ctime_ns != after.st_ctime_ns
    ):
        raise RuntimeError(f"File changed while it was being scanned: {path}")
    return digest


def _cache_path() -> Path:
    return appdata_dir() / "fscan-hash-cache.sqlite3"


def _connection(path: Path) -> sqlite3.Connection | None:
    key = str(path.resolve())
    if key in _CONNECTIONS:
        return _CONNECTIONS[key]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(key, timeout=5, check_same_thread=False)
        connection.execute(
            "CREATE TABLE IF NOT EXISTS file_hashes ("
            "path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL, "
            "ctime_ns INTEGER NOT NULL, sha256 TEXT NOT NULL)"
        )
        connection.commit()
    except (OSError, sqlite3.Error):
        connection = None
    _CONNECTIONS[key] = connection
    return connection


def flush_cache() -> None:
    global _PENDING_COMMITS
    with _CACHE_LOCK:
        for connection in _CONNECTIONS.values():
            if connection is not None:
                try:
                    connection.commit()
                except sqlite3.Error:
                    continue
        _PENDING_COMMITS = 0


def cached_sha256(path: Path, *, use_cache: bool = True) -> str:
    global _PENDING_COMMITS
    target = path.resolve()
    stat = target.stat()
    key = os.path.normcase(str(target))
    with _CACHE_LOCK:
        connection = _connection(_cache_path()) if use_cache else None
        if connection is not None:
            try:
                entry = connection.execute(
                    "SELECT size, mtime_ns, ctime_ns, sha256 FROM file_hashes WHERE path = ?",
                    (key,),
                ).fetchone()
            except sqlite3.Error:
                entry = None
            if (
                entry is not None
                and entry[0] == stat.st_size
                and entry[1] == stat.st_mtime_ns
                and entry[2] == stat.st_ctime_ns
                and isinstance(entry[3], str)
                and len(entry[3]) == 64
            ):
                return entry[3]
        digest = _stable_sha256(target, stat)
        if connection is not None:
            try:
                connection.execute(
                    "INSERT INTO file_hashes(path, size, mtime_ns, ctime_ns, sha256) "
                    "VALUES (?, ?, ?, ?, ?) ON CONFLICT(path) DO UPDATE SET "
                    "size=excluded.size, mtime_ns=excluded.mtime_ns, "
                    "ctime_ns=excluded.ctime_ns, sha256=excluded.sha256",
                    (key, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns, digest),
                )
                _PENDING_COMMITS += 1
                if _PENDING_COMMITS >= 256:
                    connection.commit()
                    _PENDING_COMMITS = 0
            except sqlite3.Error:
                pass
    return digest


atexit.register(flush_cache)


@lru_cache(maxsize=32)
def _read_hash_set_cached(path_value: str, mtime_ns: int, size: int) -> frozenset[str]:
    del mtime_ns, size
    return frozenset(_read_hash_set(Path(path_value)))


def read_hash_set(path: Path) -> set[str]:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return set()
    except OSError as exc:
        raise ValueError(f"Could not inspect hash list {path}: {exc}") from exc
    return set(_read_hash_set_cached(str(path.resolve()), stat.st_mtime_ns, stat.st_size))


def _read_hash_set(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return set()
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read hash list {path}: {exc}") from exc

    values = data.get("sha256", []) if isinstance(data, dict) else None
    if not isinstance(values, list) or not all(
        isinstance(item, str) and len(item) == 64
        and all(character in "0123456789abcdefABCDEF" for character in item)
        for item in values
    ):
        raise ValueError(f"Hash list {path} must contain a 'sha256' array of SHA-256 hashes.")
    return {item.casefold() for item in values}
