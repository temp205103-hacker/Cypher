"""Deterministic weighted file-risk scoring and local scan orchestration."""

from __future__ import annotations

from dataclasses import dataclass
import fnmatch
import os
from pathlib import Path
from typing import Any, Callable, Iterable

import psutil

from guardsnitch.fscan.hashing import cached_sha256, flush_cache
from guardsnitch.fscan.heuristics import inspect_path
from guardsnitch.fscan.trust import hash_reputation, is_excluded_path


DEFAULT_MAX_FILE_SIZE = 128 * 1024 * 1024
QUICK_MAX_FILE_SIZE = 32 * 1024 * 1024
SKIP_DIRECTORIES = {
    "$recycle.bin", "system volume information", ".git", ".hg", ".svn",
    ".venv", "venv", "node_modules", "__pycache__", "quarantine",
}


@dataclass(frozen=True)
class ScanOptions:
    full: bool = False
    usb_only: bool = False
    include_project: bool = False
    max_file_size: int | None = DEFAULT_MAX_FILE_SIZE
    ignore_file: Path | None = None


def _verdict(score: int) -> str:
    if score < 25:
        return "Clean"
    if score < 45:
        return "Low"
    if score < 70:
        return "Suspicious"
    return "Dangerous"


def score_signals(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """Score evidence repeatably; a lone weak signal cannot reach Dangerous."""
    deduplicated: dict[str, dict[str, Any]] = {}
    for signal in signals:
        signal_id = str(signal.get("id", signal.get("evidence", "")))
        if signal_id not in deduplicated:
            deduplicated[signal_id] = dict(signal)
    evidence = list(deduplicated.values())
    group_weights: dict[str, int] = {}
    group_winners: dict[str, dict[str, Any]] = {}
    for item in evidence:
        group = str(item.get("group", item.get("id")))
        weight = max(0, min(100, int(item.get("weight", 0))))
        if weight > group_weights.get(group, -1):
            group_weights[group] = weight
            group_winners[group] = item
    raw_score = sum(group_weights.values())
    strong_groups = {
        group for group, weight in group_weights.items() if weight >= 20
    }
    for item in evidence:
        group = str(item.get("group", item.get("id")))
        item["score_contribution"] = group_weights[group] if group_winners[group] is item else 0
    score = min(100, raw_score)
    if score >= 70 and len(strong_groups) < 2:
        score = 69

    independent_groups = {str(item.get("group", item.get("id"))) for item in evidence}
    if not evidence:
        confidence = "high"
    elif len(independent_groups) >= 3:
        confidence = "high"
    elif len(independent_groups) == 2:
        confidence = "medium"
    else:
        confidence = "low"
    return {
        "score": score,
        "verdict": _verdict(score),
        "confidence": confidence,
        "evidence": evidence,
    }


def _roots_from_user() -> list[Path]:
    home = Path.home()
    roots = [home / "Downloads", home / "Desktop"]
    for variable in ("TEMP", "TMP", "APPDATA", "LOCALAPPDATA"):
        value = os.getenv(variable)
        if value:
            roots.append(Path(value))
    if os.name == "nt":
        roots.extend([
            home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
            Path(os.getenv("PROGRAMDATA") or r"C:\ProgramData") / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        ])
    valid = {root for root in roots if str(root) and root.exists()}
    return sorted(valid, key=lambda item: os.path.normcase(str(item)))


def _mounted_roots(usb_only: bool) -> list[Path]:
    roots: set[Path] = set()
    try:
        partitions = psutil.disk_partitions(all=False)
    except psutil.Error as exc:
        raise RuntimeError(f"Could not list mounted drives: {exc}") from exc
    for partition in partitions:
        if not partition.mountpoint:
            continue
        if usb_only:
            if "removable" not in partition.opts.casefold():
                continue
        elif psutil.WINDOWS and "fixed" not in partition.opts.casefold():
            continue
        elif not psutil.WINDOWS and partition.fstype.casefold() in {"proc", "sysfs", "tmpfs", "devtmpfs"}:
            continue
        roots.add(Path(partition.mountpoint))
    if usb_only and not roots:
        raise RuntimeError("No mounted removable drives were found.")
    return sorted(roots, key=lambda item: os.path.normcase(str(item)))


def select_roots(*, full: bool = False, usb_only: bool = False) -> list[Path]:
    if usb_only:
        return _mounted_roots(usb_only=True)
    if full:
        roots = _mounted_roots(usb_only=False)
        if not roots:
            raise RuntimeError("No mounted local fixed drives were found.")
        return roots
    roots = _roots_from_user()
    if not roots:
        raise RuntimeError("No default scan folders were found. Use --path to choose a folder.")
    return roots


def _ignore_patterns(ignore_file: Path | None) -> list[str]:
    path = ignore_file or Path.cwd() / ".guardignore"
    if not path.is_file():
        return []
    try:
        return [
            line.strip().replace("\\", "/")
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except OSError as exc:
        raise RuntimeError(f"Could not read ignore file {path}: {exc}") from exc


def _is_ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError:
        relative = path.as_posix()
    for pattern in patterns:
        if fnmatch.fnmatchcase(relative, pattern) or fnmatch.fnmatchcase(path.name, pattern):
            return True
        if pattern.endswith("/**"):
            directory = pattern[:-3].rstrip("/")
            if relative == directory or relative.startswith(directory + "/"):
                return True
        if any(fnmatch.fnmatchcase(part, pattern.rstrip("/")) for part in Path(relative).parts):
            return True
    return False


def _iter_files(
    roots: Iterable[Path],
    patterns: list[str],
    options: ScanOptions,
    errors: list[dict[str, str]],
    skipped_size: list[int],
):
    seen: set[str] = set()
    project_root = Path(__file__).resolve().parents[2]
    for root in roots:
        if root.is_symlink():
            errors.append({"path": str(root), "error": "Symbolic-link scan roots are not followed."})
            continue
        if root.is_file():
            candidates = iter((root,))
            walk_root = root.parent
        elif root.is_dir():
            walk_root = root

            def record_walk_error(error: OSError) -> None:
                errors.append({"path": str(error.filename or root), "error": str(error)})

            def walk_files():
                for current, dirs, filenames in os.walk(
                    root, followlinks=False, onerror=record_walk_error
                ):
                    current_path = Path(current)
                    dirs[:] = [
                        name for name in dirs
                        if name.casefold() not in SKIP_DIRECTORIES
                        and not (current_path / name).is_symlink()
                        and (
                            options.include_project
                            or not is_excluded_path(current_path / name, project_root)
                        )
                    ]
                    for filename in filenames:
                        yield current_path / filename

            candidates = walk_files()
        else:
            errors.append({"path": str(root), "error": "Scan path does not exist or is inaccessible."})
            continue
        for candidate in candidates:
            try:
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                resolved = candidate.resolve()
                key = os.path.normcase(str(resolved))
                if key in seen:
                    continue
                if not options.include_project and is_excluded_path(resolved, project_root):
                    continue
                if _is_ignored(resolved, walk_root, patterns):
                    continue
                stat = resolved.stat()
                if options.max_file_size is not None and stat.st_size > options.max_file_size:
                    skipped_size[0] += 1
                    continue
                seen.add(key)
                yield resolved
            except OSError:
                errors.append({"path": str(candidate), "error": "File is inaccessible or changed during scan."})
                continue


def analyze_file(path: Path, *, use_cache: bool = True) -> dict[str, Any]:
    try:
        digest = cached_sha256(path, use_cache=use_cache)
    except OSError as exc:
        raise RuntimeError(f"Could not hash {path}: {exc}") from exc
    reputation = hash_reputation(digest)
    signals = inspect_path(path)
    if reputation == "blocked":
        signals.append({
            "id": "known-blocklist-hash",
            "group": "reputation",
            "weight": 100,
            "evidence": f"SHA-256 matches the local blocklist ({digest}).",
        })
    elif reputation in {"allowlisted", "user-allowlisted"}:
        return {
            "path": str(path),
            "sha256": digest,
            "score": 0,
            "verdict": "Clean",
            "confidence": "high",
            "evidence": [{
                "id": reputation,
                "group": "reputation",
                "weight": -100,
                "evidence": "SHA-256 matches a local allowlist.",
            }],
            "allowlisted": True,
            "explanation": "This exact file hash is on the local allowlist.",
        }

    scored = score_signals(signals)
    return {
        "path": str(path),
        "sha256": digest,
        **scored,
        "allowlisted": False,
        "explanation": (
            "Multiple independent indicators merit review."
            if len({item.get("group") for item in signals}) > 1
            else "No strong malicious indicator was established; review the listed context signals."
        ),
    }


def scan_paths(
    roots: Iterable[Path],
    *,
    options: ScanOptions | None = None,
    on_file: Callable[[Path, int], None] | None = None,
) -> dict[str, Any]:
    settings = options or ScanOptions()
    patterns = _ignore_patterns(settings.ignore_file)
    findings: list[dict[str, Any]] = []
    scanned = 0
    errors: list[dict[str, str]] = []
    skipped_size = [0]
    root_list = list(roots)

    try:
        for path in _iter_files(root_list, patterns, settings, errors, skipped_size):
            scanned += 1
            if on_file:
                on_file(path, scanned)
            try:
                result = analyze_file(path)
            except (OSError, RuntimeError, ValueError) as exc:
                errors.append({"path": str(path), "error": str(exc)})
                continue
            if result["verdict"] != "Clean":
                findings.append(result)
    finally:
        flush_cache()

    findings.sort(key=lambda item: (-int(item["score"]), str(item["path"]).casefold()))
    counts = {
        verdict: sum(item["verdict"] == verdict for item in findings)
        for verdict in ("Clean", "Low", "Suspicious", "Dangerous")
    }
    counts["Clean"] = max(0, scanned - len(errors) - len(findings))
    return {
        "files_scanned": scanned,
        "files_skipped_size": skipped_size[0],
        "risk_score": max((int(item["score"]) for item in findings), default=0),
        "counts": counts,
        "findings": findings,
        "errors": errors,
        "status": "partial" if errors else "complete",
        "what_to_do_next": (
            "Review the evidence for each finding. Quarantine or delete only after verifying the file."
            if findings
            else "No configured local indicator matched; this does not prove that files are safe."
        ),
    }
