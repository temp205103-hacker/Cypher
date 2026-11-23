# GuardSnitch.ai

GuardSnitch.ai is a Windows-first security companion with a Python command-line interface.
It brings together selected tools for browser phishing checks, VPN management, local malware
scanning, suspicious-connection alerts, and theft-protection workflows.

It is **supplementary protection**, not a replacement for Microsoft Defender, Windows Firewall,
Windows updates, or backups. See [Current limitations](#current-limitations).

## Contents

- [Requirements](#requirements)
- [Install and first-time setup](#install-and-first-time-setup)
- [Run GuardSnitch.ai](#run-guardsnitchai)
- [Web dashboard](#web-dashboard)
- [Features and how to use them](#features-and-how-to-use-them)
- [Current limitations](#current-limitations)

## Requirements

- Windows (the installer and background shield are Windows-specific).
- Python 3.9 or newer.
- PowerShell.
- Optional: OpenVPN and `.ovpn` profiles for real VPN connections and IP rotation.
- Optional: ClamAV (`clamscan`) or YARA on `PATH` for local malware scanning.

Some OpenVPN and Windows Firewall operations may require administrator privileges.

## Install and first-time setup

From the project directory, run:

```powershell
.\install.ps1
```

The installer creates a `.venv`, installs GuardSnitch.ai, then starts the first-time setup if
your name or theft-alert email is missing. Setup also asks for sender credentials, feature
preferences, and a disarm PIN. If you enable theft protection, it asks for location and webcam
consent. The current email sender uses Gmail SMTP (`smtp.gmail.com:587`); delivery requires
compatible sender credentials and explicit consent to share location.

The installer registers the reverse-shell shield to start at this Windows user's next sign-in.
To start it immediately in the current session, use `GuardSnitch.ai shield start` after activating
the environment below.

If PowerShell blocks the installer script, allow it for the current PowerShell session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

## Run GuardSnitch.ai

Activate the installed environment in each new PowerShell window:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then view help or open the CLI welcome screen:

```powershell
GuardSnitch.ai --help
GuardSnitch.ai
```

The commands `guardsnitch` and `gsnitch` are also installed as aliases. Run
`GuardSnitch.ai setup` to reopen setup.

## Web dashboard

Start the dashboard from the installed environment:

```powershell
GuardSnitch.ai --online
```

It opens a browser at `http://127.0.0.1:8787`. The dashboard binds to loopback only and is not
available to other devices on your network. Run the same command again while it is already open to
reopen the existing dashboard. Use `--port 9000` to choose another port or `--no-browser` to start
without opening a browser.

The dashboard provides clickable controls for the implemented shield, malware scan and monitor,
quarantine, VPN/IP diagnostics, theft protection, and browser-extension setup features. It asks for
confirmation before operations that can change network settings, alter startup behavior, or move,
restore, or delete files. Each completed or failed action displays a report and appears in the
dashboard's recent activity. Reports are kept in memory and limited to the latest 50 actions.

Basic profile preferences and a hashed disarm PIN can be saved in the dashboard. Use
`GuardSnitch.ai setup` for SMTP credential setup and email verification. The phishing extension
continues to run in Chrome or Edge, separately from the dashboard. Dashboard actions that require
network access (such as VPN connections, public-IP checks, or configured test-email delivery) still
use those services when you explicitly start them.

The dashboard also includes source scanning, redaction, safe download inspection, recurring scan
and IP schedules, rotation history, safe-zone management, and offline security guidance. These
tools are also available from the CLI.

## Features and how to use them

### Browser phishing checks (Chrome and Edge)

Install the unpacked extension from `browser-extension/phishing-guard`:

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select the `browser-extension/phishing-guard` folder.
4. Reload tabs that were already open.

The extension checks links on web pages against a locally cached OpenPhish community feed.
If a match is found, choose **No, block** to cancel navigation or **Yes, open anyway** to proceed.
Use the extension icon to check feed status or request an update.

The feed is downloaded from GitHub; visited URLs are checked locally and are not sent to the feed
provider. This blocklist cannot catch every phishing link. It checks page links, not URLs typed
directly into the address bar, links opened in other apps, or all redirected navigation.

### VPN and IP diagnostics

For real VPN connections, install OpenVPN, make `openvpn.exe` available on `PATH`, and place
`.ovpn` profiles in `%APPDATA%\GuardSnitch\openvpn_profiles`. You can also pass an absolute
profile path.

```powershell
GuardSnitch.ai -v -c "my-profile"
GuardSnitch.ai --vpn off
GuardSnitch.ai vpn status
GuardSnitch.ai vpn countries
GuardSnitch.ai vpn disconnect
GuardSnitch.ai vpn reconnect
GuardSnitch.ai ip status
GuardSnitch.ai ip rotate --dry-run
GuardSnitch.ai ip rotate
GuardSnitch.ai ip leak-test
```

IP rotation switches between installed OpenVPN profiles and requires an active real tunnel.
It reports whether the observed public IPv4 changed; it cannot force an ISP or VPN provider to
assign a different address. Leak diagnostics query ipify for public addresses and compare system
DNS settings with the active profile. The DNS comparison is a warning heuristic, not proof that
DNS traffic stayed in the tunnel.

For development only, `GUARDSNITCH_VPN_PROVIDER=mock` enables a simulated provider. Mock mode
does not create a VPN tunnel, encrypt traffic, change your public address, or change firewall rules.

### Malware scans and Downloads monitoring

Install ClamAV or YARA locally and make the executable available on `PATH`. ClamAV signatures
should be kept current. The included YARA rules are examples, not a complete antivirus engine.

```powershell
GuardSnitch.ai malware status
GuardSnitch.ai malware scan
GuardSnitch.ai malware scan "C:\Users\you\Downloads"
GuardSnitch.ai malware monitor start
GuardSnitch.ai malware monitor status
GuardSnitch.ai malware findings
GuardSnitch.ai quarantine list
GuardSnitch.ai quarantine isolate <finding-id>
GuardSnitch.ai quarantine restore <finding-id>
GuardSnitch.ai quarantine delete <finding-id>
GuardSnitch.ai malware monitor stop
```

Manual scans run when requested. The optional monitor scans completed files in your Downloads
folder and queues findings; it does not remove files automatically. Isolating, restoring, or
permanently deleting a file requires confirmation. Files are scanned locally and are not uploaded
by GuardSnitch.ai.

### Live reverse-shell shield

The shield monitors established connections using heuristics, then prompts when it detects
suspicious activity. Choose **Yes** to allow that endpoint for the current shield session. Choose
**No**, or do not respond within 30 seconds, to deny it. On denial, the shield attempts a scoped
Windows Firewall rule, terminates the process, and tries OpenVPN profile rotation if a real
connection and alternate profile are available.

```powershell
GuardSnitch.ai shield start
GuardSnitch.ai shield status
GuardSnitch.ai shield stop
GuardSnitch.ai shield startup install
GuardSnitch.ai shield startup status
GuardSnitch.ai shield startup uninstall
```

The installer registers the shield for this Windows user's sign-in. Detection occurs after a
connection is established, so some data may already have passed. Firewall rules may require
administrator rights. The shield can miss threats or prompt on legitimate connections.

### Theft protection

```powershell
GuardSnitch.ai theft arm
GuardSnitch.ai theft test
GuardSnitch.ai theft status
GuardSnitch.ai theft disarm
```

Location and webcam collection require consent in setup. A confirmed theft event can queue a local
alert, attempt to email the consented location to the configured theft-alert address, and lock the
Windows session. The normal Windows sign-in unlocks it. The alert is addressed to that configured
email; without sender credentials, delivery is simulated rather than sent.

`theft test` is a safe simulation: it does not lock the workstation, capture the webcam, or trigger
a live theft response. If location consent and email delivery are configured, it may send a test
email.

### Source scanning and privacy tools

```powershell
GuardSnitch.ai scan . --format json
GuardSnitch.ai scan --staged
GuardSnitch.ai redact .\notes.txt
GuardSnitch.ai explain <finding-id>
GuardSnitch.ai ask "How should I handle an exposed token?"
GuardSnitch.ai safe-run https://example.com/script.py
GuardSnitch.ai install-hook
```

The local source scanner checks for selected secret/PII patterns and risky code constructs; it is
heuristic and can produce false positives or miss vulnerabilities. `redact` writes a separate
`.redacted` file by default. `safe-run` inspects public HTTP(S) downloads as text and never executes
them. The pre-commit hook scans staged Git content and blocks a commit when it reports findings.

Recurring schedules use Windows Task Scheduler. Configure malware scans with
`GuardSnitch.ai malware schedule hourly`, `daily`, or `off`; configure IP rotation with
`GuardSnitch.ai ip schedule daily --at 03:00` or `off`. Use `GuardSnitch.ai ip history` to review
local rotation attempts and `GuardSnitch.ai ip stop` to remove its scheduled task. Trusted Wi-Fi
safe zones can be managed with `GuardSnitch.ai theft safe-zones add "Network name"`,
`remove "Network name"`, and `list`; background theft detection is not implemented.

## Current limitations

- There is no background theft-signal detector yet. Arming theft protection alone will not
  automatically detect a theft or trigger the live-event handler.
- The Downloads monitor is not a pre-execution blocker and does not monitor Windows Store installs.
  Keep Microsoft Defender real-time protection enabled.
- The reverse-shell shield is heuristic and reacts after connections are established.
- Source scanning checks selected local patterns; it is not a comprehensive vulnerability or
  malware scanner.
- Safe-zone SSIDs are stored for future signal evaluation; they do not enable background theft
  detection.
- A VPN kill switch is not implemented.

Detection is not guaranteed. Keep Windows and security software up to date, use strong
authentication, and maintain tested backups. A clean GuardSnitch.ai scan is not proof that a file
or machine is safe.
