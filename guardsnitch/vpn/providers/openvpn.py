"""OpenVPN CLI provider for Windows."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import psutil

from guardsnitch.config import appdata_dir


class OpenVpnError(RuntimeError):
    pass


class OpenVpnProvider:
    name = "openvpn"

    def __init__(self, executable: str | None = None) -> None:
        self.executable = executable or shutil.which("openvpn")
        self.profile_dir = appdata_dir() / "openvpn_profiles"
        self.pid_path = appdata_dir() / "openvpn.pid"

    def _resolve_profile(self, country_code: str) -> Path:
        value = country_code.strip()
        candidates = (
            self.profile_dir / value,
            self.profile_dir / f"{value}.ovpn",
            Path(value),
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        raise OpenVpnError(
            f"OpenVPN profile '{value}' was not found. Put it in "
            f"{self.profile_dir} or pass an absolute .ovpn path."
        )

    def connect(self, country_code: str) -> dict[str, object]:
        if not self.executable:
            raise OpenVpnError(
                "openvpn.exe was not found in PATH. Install OpenVPN and reopen PowerShell."
            )
        profile = self._resolve_profile(country_code)
        log_path = appdata_dir() / "openvpn.log"

        self.disconnect()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("", encoding="utf-8")
        self.pid_path.parent.mkdir(parents=True, exist_ok=True)
        process = subprocess.Popen(
            [
                self.executable,
                "--config",
                str(profile),
                "--log",
                str(log_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.STDOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            self.pid_path.write_text(str(process.pid), encoding="utf-8")
        except OSError as exc:
            process.terminate()
            raise OpenVpnError(f"Could not save OpenVPN process state: {exc}") from exc

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                try:
                    self.pid_path.unlink()
                except OSError:
                    pass
                raise OpenVpnError(
                    f"OpenVPN exited during startup. Check {log_path} for details."
                )
            try:
                log_text = log_path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                process.terminate()
                try:
                    self.pid_path.unlink()
                except OSError:
                    pass
                raise OpenVpnError(f"Could not read OpenVPN startup log {log_path}: {exc}") from exc
            if "Initialization Sequence Completed" in log_text:
                return {
                    "country_code": country_code,
                    "country_name": country_code,
                    "server": profile.name,
                    "profile": str(profile),
                    "simulated": False,
                    "tunnel_pid": process.pid,
                }
            time.sleep(0.25)
        process.terminate()
        try:
            self.pid_path.unlink()
        except OSError:
            pass
        raise OpenVpnError(
            f"OpenVPN did not establish the tunnel within 30 seconds. Check {log_path}."
        )

    def disconnect(self) -> None:
        if not self.pid_path.exists():
            return
        try:
            pid = int(self.pid_path.read_text(encoding="utf-8").strip())
        except (OSError, ValueError) as exc:
            raise OpenVpnError(f"Could not read the OpenVPN process ID: {exc}") from exc

        try:
            process = psutil.Process(pid)
        except psutil.NoSuchProcess:
            process = None
        except psutil.AccessDenied as exc:
            raise OpenVpnError(f"Could not inspect OpenVPN process {pid}: {exc}") from exc

        if process is not None:
            try:
                process_name = process.name().casefold()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                raise OpenVpnError(f"Could not verify process {pid} before disconnecting: {exc}") from exc
            expected_name = Path(self.executable or "openvpn.exe").name.casefold()
            if process_name not in {expected_name, "openvpn", "openvpn.exe"}:
                raise OpenVpnError(
                    f"Saved PID {pid} belongs to {process_name}, not OpenVPN; refusing to stop it."
                )
            try:
                process.terminate()
                process.wait(timeout=10)
            except psutil.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=5)
                except psutil.TimeoutExpired as exc:
                    raise OpenVpnError(f"OpenVPN process {pid} did not stop.") from exc
            except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
                raise OpenVpnError(f"Could not stop OpenVPN process {pid}: {exc}") from exc

        try:
            self.pid_path.unlink()
        except OSError as exc:
            raise OpenVpnError(f"Could not remove OpenVPN process state: {exc}") from exc
