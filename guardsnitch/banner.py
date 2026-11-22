"""Terminal branding and status presentation."""

from rich.console import Console
from rich.panel import Panel

GUARD_BANNER = r"""
  ____                 _ ____        _ _       _
 / ___|_   _  __ _ _ _| / ___| _ __ (_) |_ ___| |__
| |  _| | | |/ _` | '__| |  _ | '_ \| | __/ __| '_ \
| |_| | |_| | (_| | |  | |_| || | | | | || (__| | | |
 \____|\__,_|\__,_|_|   \____||_| |_|_|\__\___|_| |_|
"""


def show_banner(console: Console) -> None:
    console.print(GUARD_BANNER, style="bold cyan", highlight=False)
    console.print(
        Panel(
            "AI that protects. Local-first, your decisions, your evidence.",
            border_style="cyan",
            title="GuardSnitch.ai",
        )
    )
