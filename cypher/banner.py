"""Terminal branding and status presentation."""

from rich.console import Console
from rich.panel import Panel

CYPHER_BANNER = "   C Y P H E R"


def show_banner(console: Console) -> None:
    console.print(CYPHER_BANNER, style="bold cyan", highlight=False)
    console.print(
        Panel(
            "AI that protects. Local-first, your decisions, your evidence.",
            border_style="cyan",
            title="Cypher",
        )
    )
