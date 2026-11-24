"""Local, static file-protection scanning."""

from cypher.fscan.engine import ScanOptions, scan_paths, score_signals

__all__ = ["ScanOptions", "scan_paths", "score_signals"]
