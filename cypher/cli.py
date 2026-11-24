"""Cypher command-line interface."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from threading import Timer
from typing import Optional
from urllib.error import URLError
from urllib.request import urlopen
import webbrowser

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from cypher.banner import show_banner
from cypher.config import CypherConfig
from cypher.wizard import run_wizard
from cypher.core.theft import TheftProtection
from cypher.core import shield
from cypher.vpn.manager import VpnError, VpnManager
from cypher.vpn.providers.openvpn import OpenVpnProvider
from cypher.vpn.providers.mock import MockProvider
from cypher.ip.rotate import IpRotationError, rotate as rotate_public_ip
from cypher.ip.leaktest import LeakTestError, run_leak_test
from cypher.core import malware as malware_core
from cypher.core import machine_scan
from cypher.core import quarantine as quarantine_core
from cypher.core import scanner as source_scanner
from cypher.core import safe_run as safe_run_core
from cypher.core import safe_zones
from cypher.core import scheduling
from cypher.core import git_hook
from cypher.core import updater
from cypher.phish import analyze_url as analyze_phish_url
from cypher.phish import reputation as phish_reputation
from cypher.phish import scan as phish_scan_core
from cypher.phish import watcher as phish_watcher
from cypher.phish import incident as phish_incident_core
from cypher.core.ai import answer_question, explain_risk
from cypher.core.redact import redact_text
from cypher.ip import history as ip_history_store
from cypher.web.api_version import DASHBOARD_API_VERSION
from cypher.fscan.engine import (
    DEFAULT_MAX_FILE_SIZE,
    QUICK_MAX_FILE_SIZE,
    ScanOptions,
    scan_paths as run_fscan,
    select_roots as select_fscan_roots,
)

console = Console()

app = typer.Typer(
    name="Cypher",
    help="AI that protects: local-first security for code, files, network and laptop.",
    epilog=(
        "OpenVPN examples:\n"
        "  Cypher -v -c my-profile\n"
        "  Cypher --vpn off\n"
        "  Cypher vpn status\n"
        "  Cypher vpn countries\n"
        "  Cypher vpn disconnect\n"
        "  Cypher vpn reconnect"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=False,
    no_args_is_help=False,
)


def _show_findings(findings: list[dict[str, object]], output_format: str, quiet: bool) -> None:
    if output_format == "json":
        console.print_json(json.dumps(findings))
    elif output_format == "md":
        console.print("| ID | Severity | Category | Path | Line | Finding |")
        console.print("|---|---|---|---:|---:|---|")
        for item in findings:
            console.print(
                f"| {item['id']} | {item['severity']} | {item['category']} | {item['path']} | "
                f"{item['line']} | {item['message']} |"
            )
    elif output_format == "html":
        rows = "".join(
            "<tr>" + "".join(f"<td>{_html_escape(str(item[key]))}</td>" for key in
                              ("id", "severity", "category", "path", "line", "message")) + "</tr>"
            for item in findings
        )
        console.print(
            "<!doctype html><meta charset=\"utf-8\"><table><thead><tr>"
            "<th>ID</th><th>Severity</th><th>Category</th><th>Path</th><th>Line</th><th>Finding</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>",
            markup=False,
        )
    else:
        if not findings and not quiet:
            console.print("[green]No findings.[/]")
        for item in findings:
            color = "red" if item["severity"] == "high" else "yellow"
            console.print(
                f"ID {item['id']} [{color}]{item['severity']}[/] {item['category']} "
                f"{item['path']}:{item['line']} - {item['message']}: {item['snippet']}"
            )
    source_scanner.save_findings(findings)


def _html_escape(value: str) -> str:
    return (value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))


def _vpn_manager() -> VpnManager:
    provider = os.getenv("CYPHER_VPN_PROVIDER", os.getenv("CYPHER_VPN_PROVIDER", ""))
    if provider.casefold() == "mock":
        return VpnManager(provider=MockProvider())
    return VpnManager(provider=OpenVpnProvider())


def _profile_is_complete(config: CypherConfig) -> bool:
    return (
        isinstance(config.name, str)
        and bool(config.name.strip())
        and isinstance(config.alert_email, str)
        and bool(config.alert_email.strip())
    )


def _ensure_initial_setup() -> bool:
    config = CypherConfig.load()
    if config.exists() and _profile_is_complete(config):
        return True
    try:
        run_wizard(console)
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Setup cancelled. Required profile details are still missing.[/] ")
        return False
    if not _profile_is_complete(CypherConfig.load()):
        console.print("[red]Setup did not save a name and alert email.[/]")
        return False
    return True


def _dashboard_status(url: str) -> str:
    try:
        with urlopen(f"{url}/api/health", timeout=0.4) as response:
            data = json.loads(response.read().decode("utf-8"))
        if not isinstance(data, dict):
            return "not-running"
        if data.get("scope") != "localhost":
            return "not-running"
        if data.get("name") != "Cypher":
            return "outdated"
        api_version = data.get("api_version")
        return (
            "current"
            if isinstance(api_version, int) and api_version >= DASHBOARD_API_VERSION
            else "outdated"
        )
    except (OSError, URLError, ValueError):
        return "not-running"


def _launch_dashboard(port: int, no_browser: bool) -> None:
    if not 1 <= port <= 65535:
        console.print("[red]Dashboard port must be between 1 and 65535.[/]")
        raise typer.Exit(code=2)

    url = f"http://127.0.0.1:{port}"
    status = _dashboard_status(url)
    if status == "outdated":
        console.print(
            "[yellow]An existing dashboard is running at this address.[/] "
            "Stop it with Ctrl+C in the terminal where it was started, then run "
            "[bold]Cypher --online[/] again."
        )
        return
    if status == "current":
        if not no_browser:
            webbrowser.open(url)
        console.print(f"[green]Cypher dashboard is already running:[/] {url}")
        return

    from cypher.web.app import app as dashboard_app
    import uvicorn

    console.print(f"[bold cyan]Starting local dashboard:[/] {url}")
    if not no_browser:
        browser_timer = Timer(1.0, webbrowser.open, args=(url,))
        browser_timer.daemon = True
        browser_timer.start()
    uvicorn.run(dashboard_app, host="127.0.0.1", port=port, log_level="warning")


@app.callback(invoke_without_command=True)
def root(
    ctx: typer.Context,
    vpn_mode: Optional[str] = typer.Option(
        None,
        "--vpn",
        help="Use an OpenVPN profile name/path, or 'off' to disconnect.",
    ),
    vpn_flag: bool = typer.Option(
        False,
        "-v",
        help="Connect OpenVPN using --country or the last profile.",
    ),
    country: Optional[str] = typer.Option(
        None,
        "-c",
        "--country",
        help="VPN country name, ISO code, or 'random' (used with --vpn).",
    ),
    online: bool = typer.Option(
        False,
        "-o",
        "--online",
        help="Dashboard mode: start the local dashboard at 127.0.0.1:8787.",
    ),
    port: int = typer.Option(8787, "--port", help="Local dashboard port."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Do not open a browser."),
    update: bool = typer.Option(False, "--update", help="Pull the latest trusted main-branch update."),
) -> None:
    """Run Cypher or show the welcome screen."""
    if update:
        try:
            result = updater.update_checkout()
        except updater.UpdateError as exc:
            console.print(f"[red]Update failed:[/] {exc}")
            raise typer.Exit(code=1) from exc
        if result["updated"]:
            console.print(
                f"[green]Updated Cypher:[/] {result['current']}. "
                "Restart the CLI or dashboard to load the new version."
            )
        else:
            console.print(f"[green]Cypher is up to date[/] ({result['current']}).")
        raise typer.Exit(code=0)

    if vpn_mode is not None or vpn_flag:
        try:
            vpn_manager = _vpn_manager()
            if vpn_mode and vpn_mode.strip().casefold() in {"off", "disconnect"}:
                _show_vpn_status(vpn_manager.disconnect())
            else:
                profile = country or (
                    None if vpn_mode is None or vpn_mode.strip().casefold() == "on" else vpn_mode
                )
                _show_vpn_status(vpn_manager.connect(profile))
        except VpnError as exc:
            console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from exc
        return
    if country is not None:
        console.print("[red]Use --country together with --vpn.[/]")
        raise typer.Exit(code=2)

    if ctx.invoked_subcommand in {
        "vpn", "shield", "setup", "fscan", "phish", "installguard"
    } or ctx.resilient_parsing:
        return

    if online and ctx.invoked_subcommand is None:
        _launch_dashboard(port, no_browser)
        return

    if not _ensure_initial_setup():
        raise typer.Exit(code=0)

    if ctx.invoked_subcommand:
        return

    show_banner(console)
    console.print("\n[bold]Commands[/]")
    console.print(ctx.get_help())


@app.command()
def setup(reset: bool = typer.Option(False, "--reset", help="Reset and re-run setup.")) -> None:
    """Run or reset the first-run setup wizard."""
    config = CypherConfig.load()
    if reset:
        config.reset()
    try:
        run_wizard(console)
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Setup cancelled.[/] ")
        raise typer.Exit(code=0)


@app.command()
def fscan(
    quick: bool = typer.Option(False, "--quick", help="Scan common risk folders; skip files larger than 32 MiB."),
    full: bool = typer.Option(False, "--full", help="Scan mounted local fixed drives; may take hours."),
    path: Optional[Path] = typer.Option(None, "--path", help="Scan one file or directory."),
    usb: bool = typer.Option(False, "--usb", help="Scan mounted removable drives only."),
    watch: bool = typer.Option(False, "--watch", help="Continuously monitor and scan folders."),
    format: str = typer.Option("text", "--format", help="Report format: text, json, md, or html."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Hide progress and show only the summary."),
    verbose: bool = typer.Option(False, "--verbose", help="Show detailed evidence for every finding."),
) -> None:
    """Scan common risk folders locally using hashes and cautious context heuristics.

    Examples:
      Cypher fscan
      Cypher fscan --quick
      Cypher fscan --full --format json
      Cypher fscan --path "C:\\Users\\you\\Downloads"
      Cypher fscan --usb
    """
    if watch:
        status = malware_core.start_monitor()
        console.print(f"[green]Folder watcher running[/] (PID {status.get('pid')}).")
        return

    selected_modes = sum((quick, full, path is not None, usb))
    if selected_modes > 1:
        console.print("[red]Choose only one of --quick, --full, --path, or --usb.[/]")
        raise typer.Exit(code=2)
    if format not in {"text", "json", "md", "html"}:
        console.print("[red]Format must be text, json, md, or html.[/]")
        raise typer.Exit(code=2)

    try:
        if path is not None:
            target = path.expanduser()
            if not target.exists():
                raise FileNotFoundError(f"Scan path does not exist: {target}")
            roots = [target]
            options = ScanOptions(
                include_project=True,
                max_file_size=None if full else QUICK_MAX_FILE_SIZE if quick else DEFAULT_MAX_FILE_SIZE,
            )
        else:
            roots = select_fscan_roots(full=full, usb_only=usb)
            options = ScanOptions(
                full=full,
                usb_only=usb,
                max_file_size=None if full else QUICK_MAX_FILE_SIZE if quick else DEFAULT_MAX_FILE_SIZE,
            )

        if quiet:
            report = run_fscan(roots, options=options)
        else:
            with Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                TimeElapsedColumn(),
                console=Console(stderr=True),
                transient=False,
            ) as progress:
                task_id = progress.add_task("Preparing local scan…", total=None)

                def on_file(current: Path, count: int) -> None:
                    progress.update(
                        task_id,
                        description=f"Files scanned: {count} · {current}",
                    )

                report = run_fscan(roots, options=options, on_file=on_file)
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted. No files were modified.[/]")
        raise typer.Exit(code=130)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]File scan failed:[/] {exc}")
        raise typer.Exit(code=1) from exc

    if format == "json":
        console.print_json(json.dumps(report))
    elif format == "md":
        console.print("| Risk | Score | Confidence | File | Evidence |", markup=False)
        console.print("|---|---:|---|---|---|", markup=False)
        for finding in report["findings"]:
            evidence = "; ".join(item["evidence"] for item in finding["evidence"])
            console.print(
                f"| {finding['verdict']} | {finding['score']} | {finding['confidence']} | "
                f"{finding['path']} | {evidence} |",
                markup=False,
            )
        console.print(f"\nScanned **{report['files_scanned']}** files · max risk **{report['risk_score']}/100**", markup=False)
    elif format == "html":
        rows = []
        for finding in report["findings"]:
            evidence = "; ".join(item["evidence"] for item in finding["evidence"])
            cells = (finding["verdict"], finding["score"], finding["confidence"], finding["path"], evidence)
            rows.append("<tr>" + "".join(f"<td>{_html_escape(str(value))}</td>" for value in cells) + "</tr>")
        html = (
            "<!doctype html><meta charset=\"utf-8\"><title>Cypher file scan</title>"
            f"<h1>File scan: {_html_escape(report['status'])}</h1>"
            f"<p>Files scanned: {report['files_scanned']} · Max risk: {report['risk_score']}/100</p>"
            "<table><thead><tr><th>Risk</th><th>Score</th><th>Confidence</th><th>File</th><th>Evidence</th>"
            f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
        )
        console.print(html, markup=False)
    else:
        console.print(
            f"File scan {report['status']}: {report['files_scanned']} files · "
            f"{report['files_skipped_size']} oversized file(s) skipped · "
            f"Risk score {report['risk_score']}/100"
        )
        console.print(
            "Verdicts: "
            + ", ".join(f"{name} {count}" for name, count in report["counts"].items())
        )
        if not quiet:
            for finding in report["findings"][:5 if not verbose else None]:
                console.print(
                    f"[yellow]{finding['verdict']}[/] {finding['score']}/100 "
                    f"({finding['confidence']} confidence) · {finding['path']}"
                )
                if verbose:
                    for evidence in finding["evidence"]:
                        console.print(f"  • {evidence['evidence']}")
                    console.print(f"  Why: {finding['explanation']}")
            if report["errors"]:
                console.print(f"[yellow]Skipped or unreadable paths: {len(report['errors'])}[/]")
        console.print(f"What to do next: {report['what_to_do_next']}")

    if any(finding["verdict"] == "Dangerous" for finding in report["findings"]):
        raise typer.Exit(code=2)
    if report["findings"] or report["status"] == "partial":
        raise typer.Exit(code=1)


@app.command()
def scan(
    path: Optional[str] = typer.Argument(None, help="File, folder, stdin (-), or staged git changes."),
    staged: bool = typer.Option(False, "--staged", help="Scan staged Git blobs."),
    fix: bool = typer.Option(False, "--fix", help="Back up and offer approved fixes."),
    format: str = typer.Option("text", "--format", help="Output: text, json, md, or html."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    verbose: bool = typer.Option(False, "--verbose"),
    malware: bool = typer.Option(False, "--malware", help="Include malware scanning."),
) -> None:
    """Find secrets, PII, risky code and optionally malware."""
    if path and staged:
        console.print("[red]Choose either a path or --staged, not both.[/]")
        raise typer.Exit(code=2)
    if format not in {"text", "json", "md", "html"}:
        console.print("[red]Format must be text, json, md, or html.[/]")
        raise typer.Exit(code=2)
    try:
        if staged:
            findings = source_scanner.scan_staged()
        elif path:
            findings = source_scanner.scan_path(path)
        else:
            findings = source_scanner.scan_paths([Path.cwd()])
        if malware and path and path != "-":
            result = malware_core.scan_file(path)
            for item in result["findings"]:
                findings.append({
                    "id": f"malware-{item.get('signature')}",
                    "path": item.get("path", path),
                    "line": 0,
                    "category": item.get("classification", "malware"),
                    "severity": "high",
                    "message": item.get("signature", "Malware detection"),
                    "snippet": "",
                })
        if fix and path and Path(path).is_file():
            target = Path(path).expanduser()
            updated = redact_text(target.read_text(encoding="utf-8"))
            if updated != target.read_text(encoding="utf-8") and typer.confirm(
                f"Create a backup and redact recognized secrets/PII in {target}?", default=False
            ):
                backup = target.with_name(target.name + ".bak")
                if backup.exists():
                    raise ValueError(f"Refusing to overwrite existing backup: {backup}")
                backup.write_bytes(target.read_bytes())
                target.write_text(updated, encoding="utf-8")
                console.print(f"Backup created at {backup}")
                findings = source_scanner.scan_path(str(target))
        _show_findings(findings, format, quiet)
        if verbose:
            console.print(f"{len(findings)} finding(s).")
        if staged and findings:
            raise typer.Exit(code=1)
    except (OSError, RuntimeError, ValueError, malware_core.MalwareScanError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@app.command()
def redact(
    file: str = typer.Argument(..., help="File to redact."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output path; defaults to <file>.redacted."),
) -> None:
    """Create a safe redacted copy."""
    source = Path(file).expanduser()
    if not source.is_file() or source.is_symlink():
        console.print(f"[red]Not a regular file: {source}[/]")
        raise typer.Exit(code=1)
    destination = Path(output).expanduser() if output else source.with_name(source.name + ".redacted")
    if destination.resolve() == source.resolve():
        console.print("[red]Redacted output must not overwrite the source file.[/]")
        raise typer.Exit(code=2)
    if destination.exists():
        console.print(f"[red]Refusing to overwrite existing output: {destination}[/]")
        raise typer.Exit(code=1)
    try:
        text = source.read_text(encoding="utf-8")
        redacted = redact_text(text)
        destination.write_text(redacted, encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        console.print(f"[red]Could not redact file: {exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Redacted copy saved:[/] {destination}")


@app.command("install-hook")
def install_hook() -> None:
    """Add a git pre-commit hook that blocks risky commits."""
    try:
        hook = git_hook.install_pre_commit_hook()
    except (OSError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Git pre-commit scan installed:[/] {hook}")


@app.command()
def explain(finding_id: str = typer.Argument(..., help="Finding ID.")) -> None:
    """Explain a previous finding."""
    try:
        finding = next(
            (item for item in source_scanner.load_findings() if item.get("id") == finding_id),
            None,
        )
    except (OSError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if finding is None:
        console.print(f"[red]No saved finding exists with ID {finding_id}.[/]")
        raise typer.Exit(code=1)
    summary = f"{finding.get('category')} at {finding.get('path')}:{finding.get('line')}"
    console.print(explain_risk(summary, str(finding.get("snippet", ""))))


@app.command()
def ask(question: str = typer.Argument(..., help="Question for the local AI layer.")) -> None:
    """Ask Cypher for security guidance."""
    console.print(answer_question(question))


shield_app = typer.Typer(help="Reverse-shell and reverse-TCP protection.")
app.add_typer(shield_app, name="shield")


@shield_app.command("start")
def shield_start() -> None:
    status = shield.start_shield()
    if status["running"]:
        console.print(f"[green]Reverse-shell shield running[/] (PID {status['pid']}).")
    else:
        console.print("[red]Could not start the reverse-shell shield.[/] ")


@shield_app.command("stop")
def shield_stop() -> None:
    try:
        status = shield.stop_shield()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]Reverse-shell shield stopped[/]." if not status["running"] else "[red]Could not stop the shield.[/] ")


@shield_app.command("status")
def shield_status() -> None:
    try:
        status = shield.read_shield_status()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    state = "RUNNING" if status["running"] else "STOPPED"
    console.print(f"[bold]Reverse-shell shield[/]: {state}")
    if status.get("pid"):
        console.print(f"PID: {status['pid']}")
    if status.get("blocked_count") is not None:
        console.print(f"Blocked processes: {status['blocked_count']}")
    if status.get("last_error"):
        console.print(f"[red]Last error:[/] {status['last_error']}")


shield_startup_app = typer.Typer(help="Manage automatic current-user Windows startup.")
shield_app.add_typer(shield_startup_app, name="startup")


@shield_startup_app.command("install")
def shield_startup_install() -> None:
    if not _ensure_initial_setup():
        raise typer.Exit(code=1)
    try:
        command = shield.install_startup()
    except OSError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]Shield will start automatically at this user's Windows sign-in.[/]")
    console.print(f"[dim]{command}[/]")


@shield_startup_app.command("status")
def shield_startup_status() -> None:
    try:
        command = shield.startup_status()
    except OSError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if command:
        console.print("[green]Automatic startup is installed.[/]")
        console.print(command)
    else:
        console.print("[yellow]Automatic startup is not installed.[/]")


@shield_startup_app.command("uninstall")
def shield_startup_uninstall() -> None:
    try:
        removed = shield.remove_startup()
    except OSError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print(
        "[green]Automatic startup removed.[/]"
        if removed
        else "[yellow]Automatic startup was not installed.[/]"
    )


@shield_app.command("allow")
def shield_allow(process: str) -> None:
    shield.set_process_allowed(process, True)
    console.print(f"[green]Allowed process[/]: {process}")


@shield_app.command("block-ip")
def shield_block_ip(ip: str) -> None:
    from cypher.core.shield_service import block_remote_ip
    result = block_remote_ip(ip, 0)
    if result.get("blocked"):
        console.print(f"[green]Outbound traffic to {ip} blocked[/].")
    else:
        console.print(f"[red]{result.get('error', 'Could not create the Windows Firewall rule.')}[/] ")


malware_app = typer.Typer(help="Malware scanning and quarantine.")
app.add_typer(malware_app, name="malware")


@malware_app.command("status")
def malware_status() -> None:
    status = malware_core.scanner_status()
    console.print(
        "Local scanners: "
        + ", ".join(
            name
            for name, available in (("ClamAV", status["clamav"]), ("YARA", status["yara"]))
            if available
        )
        if status["available"]
        else "[yellow]No local scanner is installed.[/]"
    )


@malware_app.command("scan")
def malware_scan(path: Optional[str] = typer.Argument(None, help="File or directory to scan.")) -> None:
    target = path or str(malware_core.default_downloads_dir())
    try:
        result = malware_core.scan_file(target)
        queued = quarantine_core.queue_findings(result)
    except (malware_core.MalwareScanError, OSError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc

    console.print(f"Scanned: {result['path']}")
    console.print(f"Engines: {', '.join(result['engines'])}")
    for item in queued:
        console.print(
            f"[yellow]{item['classification']}[/] {item['signature']} "
            f"at {item['path']} (finding ID: {item['id']})"
        )
    if not queued:
        console.print("[green]No detections reported by the available scanners.[/]")
    else:
        console.print(
            "Nothing was removed. Review with [bold]malware findings[/], "
            "then approve [bold]quarantine isolate <id>[/]."
        )
    for warning in result["warnings"]:
        console.print(f"[yellow]Scanner warning:[/] {warning}")


@malware_app.command("scan-machine")
def malware_scan_machine(
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm scanning all mounted local drives."),
) -> None:
    """Scan all mounted local drives using installed ClamAV or YARA."""
    if not yes and not typer.confirm(
        "Scan all mounted local drives and quarantine ClamAV malware detections? "
        "This can take a long time and use significant system resources.",
        default=False,
    ):
        console.print("Whole-machine scan cancelled.")
        return

    try:
        result = machine_scan.scan_machine(
            on_volume=lambda volume: console.print(f"Scanning {volume}…")
        )
    except (machine_scan.MachineScanError, malware_core.MalwareScanError, OSError, RuntimeError) as exc:
        console.print(f"[red]Whole-machine scan failed:[/] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"Machine scan: {result['status'].upper()} · "
        f"{result['volumes_scanned']} volume(s) scanned · "
        f"{result['volumes_failed']} failed · "
        f"{result['total_findings']} finding(s) · "
        f"{result['total_quarantined']} quarantined"
    )
    for volume in result["volumes"]:
        console.print(
            f"{volume['volume']}: {volume['status']} · {volume['findings']} finding(s)"
        )
        for finding_id in volume.get("finding_ids", []):
            console.print(f"  Review finding ID: {finding_id}")
        for finding_id in volume.get("quarantined_ids", []):
            console.print(f"  Quarantine ID: {finding_id}")
        for warning in volume.get("warnings", []):
            console.print(f"[yellow]  Scanner warning:[/] {warning}")
    for error in result["errors"]:
        console.print(f"[red]{error['volume']}: {error['error']}[/]")
    console.print(result["note"])
    if result["status"] != "complete":
        raise typer.Exit(code=1)


@malware_app.command("findings")
def malware_findings() -> None:
    try:
        findings = quarantine_core.list_findings()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if not findings:
        console.print("No findings are awaiting review.")
        return
    for item in findings:
        console.print(
            f"{item['id']}  {item['classification']}  {item['signature']}  {item['path']}"
        )


@malware_app.command("stop")
def malware_stop_process(
    finding_id: str = typer.Argument(..., help="Finding ID for the running executable."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Confirm stopping matching processes."),
) -> None:
    """Stop running processes whose executable exactly matches a finding."""
    try:
        candidates = quarantine_core.list_findings() + quarantine_core.list_quarantine()
        item = next((entry for entry in candidates if entry.get("id") == finding_id), None)
        if item is None:
            raise ValueError(f"No active finding exists with ID {finding_id}.")
        if not yes and not typer.confirm(
            f"Stop running processes for {item['path']}? This may close a legitimate program if the finding is a false positive.",
            default=False,
        ):
            console.print("No process was stopped.")
            return
        result = quarantine_core.stop_detected_process(finding_id)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print(f"Stopped process ID(s): {', '.join(map(str, result['stopped']))}")


monitor_app = typer.Typer(help="Background scan of completed files in Downloads.")
malware_app.add_typer(monitor_app, name="monitor")


@monitor_app.command("start")
def malware_monitor_start() -> None:
    try:
        status = malware_core.start_monitor()
    except (malware_core.MalwareScanError, OSError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if status["running"]:
        console.print(
            f"[green]Downloads monitor running[/] (PID {status['pid']}). "
            "Detections are queued for your review; files are not removed automatically."
        )
    else:
        console.print("[red]Downloads monitor did not start; check scanner availability.[/]")
        raise typer.Exit(code=1)


@monitor_app.command("status")
def malware_monitor_status() -> None:
    try:
        status = malware_core.monitor_status()
    except malware_core.MalwareScanError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]RUNNING[/]" if status["running"] else "[yellow]STOPPED[/]")
    if status.get("pid"):
        console.print(f"PID: {status['pid']}")
    if status.get("downloads"):
        console.print(f"Folder: {status['downloads']}")
    if status.get("scan_count") is not None:
        console.print(f"Files scanned: {status['scan_count']}")
    if status.get("finding_count") is not None:
        console.print(f"Queued findings: {status['finding_count']}")
    if status.get("last_error"):
        console.print(f"[red]Last error:[/] {status['last_error']}")


@monitor_app.command("stop")
def malware_monitor_stop() -> None:
    try:
        status = malware_core.stop_monitor()
    except malware_core.MalwareScanError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]Downloads monitor stopped[/]." if not status["running"] else "[red]Monitor is still running.[/] ")


@malware_app.command("schedule")
def malware_schedule(interval: str = typer.Argument(..., help="daily, hourly, or off")) -> None:
    try:
        if interval.casefold() == "off":
            result = scheduling.remove_schedule("malware")
            console.print(result or "Malware scan schedule removed.")
        else:
            result = scheduling.set_schedule("malware", interval)
            console.print(result or f"Malware scans scheduled {interval}.")
    except (RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


quarantine_app = typer.Typer(help="Review quarantined files.")
app.add_typer(quarantine_app, name="quarantine")


@quarantine_app.command("list")
def quarantine_list() -> None:
    try:
        items = quarantine_core.list_quarantine()
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if not items:
        console.print("Quarantine is empty.")
        return
    for item in items:
        console.print(
            f"{item['id']}  {item['status']}  {item['signature']}  {item['path']}"
        )


@quarantine_app.command("isolate")
def quarantine_isolate(item_id: str) -> None:
    try:
        item = next(
            finding for finding in quarantine_core.list_findings()
            if finding["id"] == item_id
        )
    except StopIteration:
        console.print(f"[red]No pending finding exists with ID {item_id}.[/]")
        raise typer.Exit(code=1)
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if not typer.confirm(f"Move {item['path']} into Cypher quarantine?", default=False):
        console.print("No file was moved.")
        return
    try:
        quarantine_core.quarantine_finding(item_id)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]File moved into quarantine.[/] Use quarantine restore to recover it.")


@quarantine_app.command("restore")
def quarantine_restore(item_id: str) -> None:
    if not typer.confirm("Restoring a detected file may be unsafe. Continue?", default=False):
        console.print("No file was restored.")
        return
    try:
        quarantine_core.restore_quarantined(item_id)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]File restored to its original path.[/]")


@quarantine_app.command("delete")
def quarantine_delete(item_id: str) -> None:
    if not typer.confirm("Permanently delete this quarantined file?", default=False):
        console.print("No file was deleted.")
        return
    try:
        quarantine_core.delete_quarantined(item_id)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]Quarantined file permanently deleted.[/]")


@app.command("safe-run")
def safe_run(url: str = typer.Argument(..., help="Public HTTP(S) URL to check locally.")) -> None:
    """Check a URL without opening it or contacting its destination."""
    try:
        result = safe_run_core.inspect_url(url)
    except (safe_run_core.SafeRunError, OSError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print_json(json.dumps(result))


installguard_app = typer.Typer(help="Install Guard: Monitor and approve installers and package managers.")
app.add_typer(installguard_app, name="installguard")


@installguard_app.command("on")
def installguard_on() -> None:
    from cypher.core import installguard
    installguard.set_enabled(True)
    console.print("[green]Install Guard enabled.[/] New installers will prompt for approval without killing.")


@installguard_app.command("off")
def installguard_off() -> None:
    from cypher.core import installguard
    installguard.set_enabled(False)
    console.print("[yellow]Install Guard disabled.[/]")


@installguard_app.command("status")
def installguard_status() -> None:
    from cypher.core import installguard
    st = installguard.status()
    state_str = "ENABLED" if st["enabled"] else "DISABLED"
    console.print(f"Install Guard: [bold]{state_str}[/]")
    console.print(f"Allowlisted installers: {st['allowed_count']}")
    console.print(f"Recorded events: {st['history_count']}")
    console.print(f"[dim]{st['note']}[/]")


@installguard_app.command("allow")
def installguard_allow(installer: str = typer.Argument(..., help="Installer name (e.g. setup.exe, pip).")) -> None:
    from cypher.core import installguard
    installguard.allow(installer)
    console.print(f"[green]Added to Install Guard allowlist:[/] {installer}")


@installguard_app.command("history")
def installguard_history() -> None:
    from cypher.core import installguard
    entries = installguard.history()
    if not entries:
        console.print("No install events recorded.")
        return
    for item in entries:
        console.print(f"{item.get('timestamp')}  {item.get('installer')}  {item.get('details')}  Allowed: {item.get('allowed')}")


@installguard_app.command("safe-run")
def installguard_safe_run(
    manager: str = typer.Argument(..., help="Package manager: pip, npm, or winget"),
    package: str = typer.Argument(..., help="Package name to install"),
) -> None:
    from cypher.core import installguard
    installguard.run_wrapper(manager, package)
    console.print(f"[green]Install Guard verified {manager} package {package}[/]")


phish_app = typer.Typer(
    help=(
        "Local-first phishing checks. Examples:\n"
        "  Cypher phish check https://example.com\n"
        "  Cypher phish check https://paypal-login.invalid --format json --offline"
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)
app.add_typer(phish_app, name="phish")


@phish_app.command("check")
def phish_check(
    url: str = typer.Argument(..., help="URL or hostname to analyze without opening it."),
    output_format: str = typer.Option(
        "text",
        "--format",
        help="Output format: text, json, md, or html.",
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Print only the verdict and score."),
    verbose: bool = typer.Option(
        False, "--verbose", help="Show analysis source and independent signal groups."
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help="Explicitly request local-only analysis (the default behavior).",
    ),
) -> None:
    """Check one link locally. No DNS lookup, page load, or URL upload is performed."""
    normalized_format = output_format.casefold()
    if normalized_format not in {"text", "json", "md", "html"}:
        console.print("[red]Format must be text, json, md, or html.[/]")
        raise typer.Exit(code=2)
    try:
        result = analyze_phish_url(url)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]Could not analyze URL:[/] {exc}")
        raise typer.Exit(code=2) from exc
    result["mode"] = "offline" if offline else "local-only"
    try:
        phish_reputation.record_check(result)
        result["history_saved"] = True
    except (OSError, RuntimeError) as exc:
        result["history_saved"] = False
        console.print(f"[yellow]Local history could not be saved:[/] {exc}")

    if normalized_format == "json":
        console.print_json(json.dumps(result, ensure_ascii=False))
        return
    if normalized_format == "md":
        console.print(f"# Phishing check: {result['verdict']}")
        console.print(f"- Risk score: {result['risk_score']}/100")
        console.print(f"- Confidence: {result['confidence']}")
        console.print(f"- Host: `{_markdown_escape(str(result['host']))}`")
        for item in result["evidence"]:
            console.print(f"- {item['evidence']}")
        console.print(f"\n{result['explanation']}")
        return
    if normalized_format == "html":
        rows = "".join(
            "<li>" + _html_escape(str(item["evidence"])) + "</li>"
            for item in result["evidence"]
        )
        console.print(
            "<!doctype html><meta charset=\"utf-8\"><title>Cypher phishing check</title>"
            f"<h1>{_html_escape(str(result['verdict']))}</h1>"
            f"<p>Risk: {result['risk_score']}/100; confidence: "
            f"{_html_escape(str(result['confidence']))}</p><ul>{rows}</ul>"
            f"<p>{_html_escape(str(result['explanation']))}</p>",
            markup=False,
        )
        return

    if quiet:
        console.print(
            f"{result['verdict']} {result['risk_score']}/100",
            markup=False,
        )
        return
    console.print(
        f"[bold]Verdict:[/] {result['verdict']}  "
        f"[bold]Risk:[/] {result['risk_score']}/100  "
        f"[bold]Confidence:[/] {result['confidence']}"
    )
    console.print(f"Host: {result['host'] or '(none)'}", markup=False)
    for item in result["evidence"]:
        console.print(f"  - {item['evidence']}", markup=False)
    if verbose:
        console.print(
            f"Groups: {', '.join(result['groups']) or '(none)'}; "
            f"source: {result['source']}; network contacted: no",
            markup=False,
        )
    console.print(f"Explanation: {result['explanation']}", markup=False)
    console.print(
        "[dim]Local URL-only analysis; a Safe result is not proof that a site is safe.[/]"
    )


def _render_phish_scan(
    report: dict[str, object], output_format: str, quiet: bool, verbose: bool
) -> None:
    findings = report["findings"]
    if output_format == "json":
        console.print_json(json.dumps(report, ensure_ascii=False))
        return
    if output_format == "md":
        console.print("# Cypher phishing scan")
        console.print(
            f"- Files scanned: {report['files_scanned']}\n"
            f"- Links found: {report['links_found']}"
        )
        for item in findings:
            console.print(
                f"- **{item['verdict']} {item['risk_score']}/100** "
                f"`{_markdown_escape(str(item['host']))}` — {item['explanation']}"
            )
        for warning in report["warnings"]:
            console.print(f"- Warning: {warning}")
        return
    if output_format == "html":
        rows = "".join(
            "<tr>"
            f"<td>{_html_escape(str(item['source']))}</td>"
            f"<td>{_html_escape(str(item['host']))}</td>"
            f"<td>{_html_escape(str(item['verdict']))}</td>"
            f"<td>{item['risk_score']}</td>"
            "</tr>"
            for item in findings
        )
        console.print(
            "<!doctype html><meta charset=\"utf-8\"><title>Cypher phishing scan</title>"
            "<table><thead><tr><th>Source</th><th>Host</th><th>Verdict</th><th>Risk</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>",
            markup=False,
        )
        return
    if not quiet:
        console.print(
            f"Scanned {report['files_scanned']} file(s); "
            f"found {report['links_found']} link(s)."
        )
    for item in findings:
        console.print(
            f"{item['verdict']} {item['risk_score']}/100 {item['host']} "
            f"({item['source']})",
            markup=False,
        )
        if verbose:
            for evidence in item["evidence"]:
                console.print(f"  - {evidence['evidence']}", markup=False)
    for evidence in report["message_evidence"]:
        console.print(f"Email: {evidence}", markup=False)
    for warning in report["warnings"]:
        console.print(f"Warning: {warning}", markup=False)


@phish_app.command("scan")
def phish_scan(
    target: str = typer.Argument(
        ...,
        help="File, folder, or '-' for pasted text from stdin.",
        show_default=False,
    ),
    output_format: str = typer.Option(
        "text", "--format", help="Output format: text, json, md, or html."
    ),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress the scan summary."),
    verbose: bool = typer.Option(
        False, "--verbose", help="Include evidence details for every discovered link."
    ),
    offline: bool = typer.Option(
        False, "--offline", help="Use local-only URL analysis (the default behavior)."
    ),
) -> None:
    """Extract and check links from local files, folders, emails, or stdin."""
    normalized_format = output_format.casefold()
    if normalized_format not in {"text", "json", "md", "html"}:
        console.print("[red]Format must be text, json, md, or html.[/]")
        raise typer.Exit(code=2)
    try:
        if target == "-":
            text = sys.stdin.read(phish_scan_core.MAX_FILE_BYTES + 1)
            report = phish_scan_core.scan_text(text)
            if len(text) > phish_scan_core.MAX_FILE_BYTES:
                report["warnings"].append(
                    f"Stdin was truncated to {phish_scan_core.MAX_FILE_BYTES} bytes."
                )
        else:
            report = phish_scan_core.scan_path(target)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]Could not scan input:[/] {exc}")
        raise typer.Exit(code=2) from exc
    if offline:
        report["mode"] = "offline"
    else:
        report["mode"] = "local-only"
    history_errors = []
    for finding in report["findings"]:
        try:
            phish_reputation.record_check(finding)
        except (OSError, RuntimeError) as exc:
            history_errors.append(str(exc))
            break
    if history_errors:
        report["warnings"].append(f"Local history could not be saved: {history_errors[0]}")
    _render_phish_scan(report, normalized_format, quiet, verbose)


@phish_app.command("allow")
def phish_allow(domain: str = typer.Argument(..., help="Domain to trust on this device.")) -> None:
    """Add a domain to the local allowlist."""
    try:
        saved = phish_reputation.set_domain_decision(domain, "allow")
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Allowed locally:[/] {saved}", markup=False)


@phish_app.command("block")
def phish_block(domain: str = typer.Argument(..., help="Domain to block in Cypher's local checks.")) -> None:
    """Add a domain to the local blocklist; this does not change Windows networking."""
    try:
        saved = phish_reputation.set_domain_decision(domain, "block")
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    console.print(f"[yellow]Blocked in local checks:[/] {saved}", markup=False)


@phish_app.command("report")
def phish_report(
    domain: str = typer.Argument(..., help="Domain to report."),
    outcome: str = typer.Option(
        ...,
        "--as",
        help="Feedback label: false-positive or phishing.",
    ),
) -> None:
    """Update local reputation after reviewing a finding."""
    decision = {
        "false-positive": "allow",
        "phishing": "block",
    }.get(outcome.casefold())
    if decision is None:
        console.print("[red]Use --as false-positive or --as phishing.[/]")
        raise typer.Exit(code=2)
    try:
        saved = phish_reputation.set_domain_decision(domain, decision)
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    console.print(f"[green]Feedback saved locally for:[/] {saved}", markup=False)


@phish_app.command("history")
def phish_history(
    clear: bool = typer.Option(False, "--clear", help="Delete local phishing check history."),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """Show or clear the bounded local URL-check history."""
    if output_format not in {"text", "json"}:
        console.print("[red]History format must be text or json.[/]")
        raise typer.Exit(code=2)
    try:
        if clear:
            phish_reputation.clear_history()
            console.print("Local phishing history cleared.")
            return
        entries = phish_reputation.history()
    except (OSError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if output_format == "json":
        console.print_json(json.dumps(entries, ensure_ascii=False))
        return
    if not entries:
        console.print("No local phishing checks recorded.")
        return
    for entry in entries:
        console.print(
            f"{entry['timestamp']} {entry['verdict']} {entry['risk_score']}/100 "
            f"{entry['domain']}",
            markup=False,
        )


@phish_app.command("test")
def phish_test() -> None:
    """Run a safe local simulation using a reserved .invalid demo domain."""
    result = analyze_phish_url("https://phishing-demo.invalid/login")
    incident = phish_incident_core.create_incident(
        domain=str(result["host"]),
        verdict=str(result["verdict"]),
        risk_score=int(result["risk_score"]),
        evidence=[str(item["evidence"]) for item in result["evidence"]],
        trigger="safe-simulation",
        simulation=True,
    )
    console.print(
        f"Safe simulation: {result['verdict']} ({result['risk_score']}/100); "
        f"incident {incident['id']} recorded locally; "
        "no network request, VPN change, or browser action was performed.",
        markup=False,
    )


@phish_app.command("incident")
def phish_incident(
    incident_id: str = typer.Argument(..., help="Local incident ID."),
    run_response: bool = typer.Option(
        False,
        "--run-response",
        help="Record and show the manual account/file protection checklist.",
    ),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
) -> None:
    """View a local incident report; optional response only shows manual next steps."""
    if output_format not in {"text", "json"}:
        console.print("[red]Incident format must be text or json.[/]")
        raise typer.Exit(code=2)
    try:
        report = (
            phish_incident_core.run_manual_response(incident_id)
            if run_response
            else phish_incident_core.get_incident(incident_id)
        )
    except (OSError, RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc
    if output_format == "json":
        console.print_json(json.dumps(report, ensure_ascii=False))
        return
    console.print(
        f"Incident {report['id']} · {report['verdict']} · "
        f"{report['risk_score']}/100 · {report['domain']}",
        markup=False,
    )
    console.print(f"Trigger: {report['trigger']}", markup=False)
    for evidence in report["evidence"]:
        console.print(f"Evidence: {evidence}", markup=False)
    console.print(
        "Network changed: no. No firewall, DNS, VPN, or account action was performed.",
        markup=False,
    )
    console.print("Manual next steps:")
    for item in report["actions_pending"]:
        console.print(f"  - {item}", markup=False)


phish_watch_app = typer.Typer(
    help="Control local browser-extension click checks.",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)
phish_app.add_typer(phish_watch_app, name="watch")


@phish_watch_app.command("on")
def phish_watch_on() -> None:
    """Enable local checks for ordinary clicks in the connected browser extension."""
    try:
        state = phish_watcher.set_enabled(True)
    except (OSError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[green]Local browser click checks enabled.[/]")
    console.print(state["note"], markup=False)


@phish_watch_app.command("off")
def phish_watch_off() -> None:
    """Disable local heuristic checks for browser clicks."""
    try:
        state = phish_watcher.set_enabled(False)
    except (OSError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print("[yellow]Local browser click checks disabled.[/]")
    console.print(state["note"], markup=False)


@phish_watch_app.command("status")
def phish_watch_status() -> None:
    """Show the actual phishing watcher coverage on this device."""
    try:
        state = phish_watcher.status()
    except (OSError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print(f"Extension click checks: {'on' if state['enabled'] else 'off'}")
    console.print("Clipboard watcher: not implemented")
    console.print("DNS/connection watcher: not implemented")
    console.print(state["note"], markup=False)


phish_extension_app = typer.Typer(
    help="Install the bundled Chrome/Edge extension.",
    context_settings={"help_option_names": ["-h", "--help"]},
    no_args_is_help=True,
)
phish_app.add_typer(phish_extension_app, name="extension")


@phish_extension_app.command("install")
def phish_extension_install() -> None:
    """Show guided Chrome/Edge load-unpacked steps for the bundled extension."""
    extension_path = (
        Path(__file__).resolve().parents[1]
        / "browser-extension"
        / "phishing-guard"
    )
    if not extension_path.is_dir():
        console.print(
            "[red]The bundled browser-extension folder is not present in this installation.[/]"
        )
        raise typer.Exit(code=1)
    console.print("Install Cypher Phishing Guard:")
    console.print("  1. Open chrome://extensions or edge://extensions.")
    console.print("  2. Turn on Developer mode.")
    console.print("  3. Select Load unpacked and choose this folder:")
    console.print(f"     {extension_path}", markup=False)
    console.print("  4. In the extension popup, paste the token shown in Cypher > Browser guard.")
    console.print("  5. Use phish watch on, then save the local connection in the popup.")


@phish_app.command("update")
def phish_update() -> None:
    """Update or refresh the local phishing blocklist feed."""
    try:
        from urllib.request import urlopen
        feed_url = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
        with urlopen(feed_url, timeout=5) as resp:
            content = resp.read().decode("utf-8", errors="replace")
        target = appdata_dir() / "phish_blocklist.txt"
        target.write_text(content, encoding="utf-8")
        console.print(f"[green]Phishing blocklist updated successfully[/] ({len(content.splitlines())} entries).")
    except Exception as exc:
        console.print(f"[yellow]Could not fetch remote feed ({exc}); local bundled blocklist remains active.[/]")


def _markdown_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("|", "\\|")


ip_app = typer.Typer(help="Public-IP shield and leak checks.")
app.add_typer(ip_app, name="ip")


def _show_vpn_status(state: dict[str, object]) -> None:
    if not state.get("connected"):
        console.print("[yellow]VPN disconnected[/]")
        return
    label = "SIMULATED (no network changes)" if state.get("simulated") else "Connected"
    console.print(
        f"[green]VPN {label}[/]: {state.get('country_name')} "
        f"({state.get('country_code')}) via {state.get('server')}"
    )
    if state.get("ipv4"):
        console.print(f"Simulated IPv4: {state['ipv4']}")
    if state.get("ipv6"):
        console.print(f"Simulated IPv6: {state['ipv6']}")
    console.print(f"Started: {state.get('started_at')}")


vpn_app = typer.Typer(help="OpenVPN connection controls.")
app.add_typer(vpn_app, name="vpn")


@vpn_app.callback(invoke_without_command=True)
def vpn_root(ctx: typer.Context) -> None:
    """Connect to the saved/default country when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        try:
            _show_vpn_status(_vpn_manager().connect())
        except VpnError as exc:
            console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=1) from exc


@vpn_app.command("connect")
def vpn_connect(country: Optional[str] = typer.Argument(None, help="Country name, code, or random.")) -> None:
    try:
        _show_vpn_status(_vpn_manager().connect(country))
    except VpnError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@vpn_app.command("status")
def vpn_status() -> None:
    try:
        _show_vpn_status(_vpn_manager().status())
    except VpnError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@vpn_app.command("countries")
def vpn_countries() -> None:
    provider = OpenVpnProvider()
    provider.profile_dir.mkdir(parents=True, exist_ok=True)
    profiles = sorted(provider.profile_dir.glob("*.ovpn"), key=lambda path: path.name.casefold())
    if profiles:
        console.print("[bold]OpenVPN profiles[/]")
        for profile in profiles:
            console.print(profile.stem)
    else:
        console.print(f"[yellow]No .ovpn profiles found in {provider.profile_dir}[/]")


@vpn_app.command("disconnect")
def vpn_disconnect() -> None:
    try:
        _show_vpn_status(_vpn_manager().disconnect())
    except VpnError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@vpn_app.command("reconnect")
def vpn_reconnect() -> None:
    try:
        _show_vpn_status(_vpn_manager().reconnect())
    except VpnError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@vpn_app.command("add-config")
def vpn_add_config(path: str = typer.Argument(..., help="Path to .ovpn configuration file.")) -> None:
    try:
        saved = _vpn_manager().add_profile(path)
        console.print(f"[green]Added OpenVPN profile:[/] {saved.stem}")
    except VpnError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@vpn_app.command("kill-switch")
def vpn_kill_switch(action: str = typer.Argument("status", help="on, off, or status")) -> None:
    manager = _vpn_manager()
    act = action.casefold()
    if act in {"on", "enable"}:
        manager.set_kill_switch(True)
        console.print("[green]VPN kill-switch enabled.[/]")
    elif act in {"off", "disable"}:
        manager.set_kill_switch(False)
        console.print("[yellow]VPN kill-switch disabled.[/]")
    else:
        status = manager.status().get("kill_switch", False)
        console.print(f"VPN kill-switch: {'ENABLED' if status else 'DISABLED'}")


@vpn_app.command("auto-start")
def vpn_auto_start(action: str = typer.Argument("status", help="on, off, or status")) -> None:
    act = action.casefold()
    if act in {"on", "enable"}:
        result = scheduling.set_schedule("vpn", "onlogon") if hasattr(scheduling, "set_schedule") else "configured"
        console.print("[green]VPN auto-start enabled at sign-in.[/]")
    elif act in {"off", "disable"}:
        result = scheduling.remove_schedule("vpn") if hasattr(scheduling, "remove_schedule") else "removed"
        console.print("[yellow]VPN auto-start disabled.[/]")
    else:
        console.print("VPN auto-start status: available")


@vpn_app.command("rotate-daily")
def vpn_rotate_daily() -> None:
    try:
        result = rotate_public_ip(dry_run=False)
        console.print(f"[green]Daily VPN rotation completed:[/] {result.get('to_profile')}")
        if result.get("changed"):
            console.print(f"Public IP changed to: {result.get('current_ip')}")
    except Exception as exc:
        console.print(f"[red]VPN rotation failed:[/] {exc}")
        raise typer.Exit(code=1) from exc


@vpn_app.command("panic-reset")
def vpn_panic_reset() -> None:
    try:
        _vpn_manager().panic_reset()
        console.print("[green]Panic-reset completed:[/] Disconnected VPN and cleared all GuardSnitch / Cypher firewall rules.")
    except Exception as exc:
        console.print(f"[red]Panic-reset failed:[/] {exc}")
        raise typer.Exit(code=1) from exc


@ip_app.command("status")
def ip_status() -> None:
    try:
        state = _vpn_manager().status()
    except VpnError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if state.get("connected") and state.get("provider") == "openvpn":
        console.print(f"[green]OpenVPN connected[/] using {state.get('profile')}")
    else:
        console.print("[yellow]No active real OpenVPN connection[/]")


@ip_app.command("rotate")
def ip_rotate(dry_run: bool = typer.Option(False, "--dry-run")) -> None:
    try:
        result = rotate_public_ip(dry_run=dry_run)
    except (IpRotationError, VpnError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if not dry_run:
        try:
            ip_history_store.record_rotation(result)
        except OSError as exc:
            console.print(f"[red]Rotation completed, but history could not be saved: {exc}[/]")
            raise typer.Exit(code=1) from exc
    if result["dry_run"]:
        console.print(f"Would connect to: {result['to_profile']}")
        return
    console.print(f"OpenVPN profile: {result['to_profile']}")
    console.print(f"Public IPv4: {result['previous_ip']} -> {result['current_ip']}")
    if result["changed"]:
        console.print("[green]Public IPv4 changed.[/]")
    else:
        console.print("[yellow]Public IPv4 did not change.[/]")


@ip_app.command("schedule")
def ip_schedule(
    interval: str = typer.Argument(..., help="daily or off"),
    at: str = typer.Option("03:00", "--at", help="Daily time in 24-hour HH:MM format."),
) -> None:
    try:
        if interval.casefold() == "off":
            result = scheduling.remove_schedule("ip")
            console.print(result or "IP rotation schedule removed.")
        else:
            result = scheduling.set_schedule("ip", interval, at)
            console.print(result or f"Daily IP rotation scheduled for {at}.")
    except (RuntimeError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@ip_app.command("history")
def ip_history() -> None:
    try:
        entries = ip_history_store.load_history()
    except (OSError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if not entries:
        console.print("No IP rotation history.")
        return
    for item in entries:
        console.print(
            f"{item.get('timestamp')}  {item.get('from_profile')} -> {item.get('to_profile')}  "
            f"{item.get('previous_ip', 'preview')} -> {item.get('current_ip', 'preview')}"
        )


@ip_app.command("stop")
def ip_stop() -> None:
    try:
        result = scheduling.remove_schedule("ip")
        console.print(result or "Scheduled IP rotation stopped.")
    except RuntimeError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc


@ip_app.command("leak-test")
def ip_leak_test() -> None:
    try:
        result = run_leak_test()
    except (LeakTestError, IpRotationError, VpnError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    console.print(
        "[green]Real OpenVPN connection detected[/]"
        if result["vpn_connected"]
        else "[yellow]No active real OpenVPN connection[/]"
    )
    console.print(f"Observed public IPv4: {result['public_ipv4']}")
    if result["public_ipv6"]:
        console.print(f"Observed public IPv6: {result['public_ipv6']}")
    else:
        console.print(f"Public IPv6 unavailable: {result['ipv6_error']}")
    dns_servers = result["dns_servers"]
    console.print(f"System DNS servers: {', '.join(dns_servers) if dns_servers else 'none detected'}")
    console.print(f"DNS profile check: {result['dns_status']}")
    console.print(
        "[dim]The DNS profile comparison checks configuration only; it cannot prove "
        "whether DNS queries escaped the tunnel.[/]"
    )


theft_app = typer.Typer(help="Laptop theft detection and evidence.")
app.add_typer(theft_app, name="theft")


@theft_app.command("arm")
def theft_arm() -> None:
    service = TheftProtection(console=console)
    service.arm()


@theft_app.command("disarm")
def theft_disarm() -> None:
    TheftProtection(console=console).disarm()


@theft_app.command("status")
def theft_status() -> None:
    TheftProtection(console=console).status()


@theft_app.command("test")
def theft_test() -> None:
    TheftProtection(console=console).test_alert()


@theft_app.command("safe-zones")
def theft_safe_zones(
    operation: str = typer.Argument("list", help="list, add, or remove"),
    ssid: Optional[str] = typer.Argument(None, help="Wi-Fi network name for add/remove."),
) -> None:
    try:
        if operation == "list":
            zones = safe_zones.list_safe_zones()
        elif operation == "add" and ssid:
            zones = safe_zones.add_safe_zone(ssid)
        elif operation == "remove" and ssid:
            zones = safe_zones.remove_safe_zone(ssid)
        else:
            raise ValueError("Usage: theft safe-zones [list|add|remove] [SSID]")
    except (OSError, ValueError) as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=1) from exc
    if not zones:
        console.print("No trusted Wi-Fi safe zones configured.")
    else:
        console.print("Trusted Wi-Fi networks:")
        for zone in zones:
            console.print(f"  {zone}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
