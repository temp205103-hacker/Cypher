# Cypher

Cypher is a Windows-first security companion with a Python command-line interface.
It brings together selected tools for browser phishing checks, VPN management, local malware
scanning, suspicious-connection alerts, and theft-protection workflows.

It is **supplementary protection**, not a replacement for Microsoft Defender, Windows Firewall,
Windows updates, or backups. See [Current limitations](#current-limitations).

## Contents

- [Requirements](#requirements)
- [Install and first-time setup](#install-and-first-time-setup)
- [Run Cypher](#run-cypher)
- [Web dashboard](#web-dashboard)
- [Updating Cypher](#updating-cypher)
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

The installer creates a `.venv`, installs Cypher, then starts the first-time setup if
your name or theft-alert email is missing. Setup also asks for sender credentials, feature
preferences, and a disarm PIN. If you enable theft protection, it asks for location and webcam
consent. The current email sender uses Gmail SMTP (`smtp.gmail.com:587`); delivery requires
compatible sender credentials and explicit consent to share location.

The installer registers the reverse-shell shield to start at this Windows user's next sign-in.
To start it immediately in the current session, use `Cypher shield start` after activating
the environment below.

If PowerShell blocks the installer script, allow it for the current PowerShell session only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1
```

## Run Cypher

Activate the installed environment in each new PowerShell window:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then view help or open the CLI welcome screen:

```powershell
Cypher --help
Cypher
```

Run `Cypher setup` to reopen setup.

## Web dashboard

Start the dashboard from the installed environment:

```powershell
Cypher --online
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
`Cypher setup` for SMTP credential setup and email verification. The phishing extension
continues to run in Chrome or Edge, separately from the dashboard. Dashboard actions that require
network access (such as VPN connections, public-IP checks, or configured test-email delivery) still
use those services when you explicitly start them.

The dashboard also includes source scanning, redaction, safe download inspection, recurring scan
and IP schedules, rotation history, safe-zone management, and offline security guidance. These
tools are also available from the CLI.

## Updating Cypher

The dashboard checks the trusted `main` branch and shows a red dot on the update icon when newer
commits are available. Click the icon to fast-forward the checkout. The CLI equivalent is:

```powershell
Cypher --update
```

Updates require a Git clone with the expected GitHub `origin`, the `main` branch, and no local
changes. Updates do not install dependencies; run `.\install.ps1` if an update changes project
dependencies. Restart the dashboard or CLI after an update to load the new code. If updating is
unavailable, use `git pull origin main` from the repository directory to see Git's detailed error.

## Features and how to use them

### Browser phishing checks (Chrome and Edge)

Install the unpacked extension from `browser-extension/phishing-guard`:

1. Open `chrome://extensions` or `edge://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select the `browser-extension/phishing-guard` folder.
4. Reload tabs that were already open.

The extension checks links on web pages against a locally cached OpenPhish community feed and
blocks matching browser requests, including links pasted into the address bar. Matching links on
pages also show a warning. Use the extension icon to check feed status or request an update.

The feed is downloaded from GitHub; URLs you visit are checked locally and are not sent to the feed
provider. This blocklist cannot catch every phishing link, and protection is unavailable when the
feed has not loaded. It protects Chrome/Edge only, not links opened in other apps.

### VPN and IP diagnostics

For real VPN connections, install OpenVPN and make `openvpn.exe` available on `PATH`. In the web
dashboard's **Network & VPN** page, follow OpenVPN Cloud/CloudConnexa's account setup, then import
the `.ovpn` profile downloaded from the provider. Imported profiles are stored in
`%APPDATA%\Cypher\openvpn_profiles` and can be selected to connect or disconnect from the dashboard.
CloudConnexa account creation requires OpenVPN's email verification and Cloud ID setup, so those
provider-hosted signup steps cannot be completed inside Cypher. Existing profiles are migrated to
the same profile directory. You can also pass an absolute profile path to the CLI.

```powershell
Cypher -v -c "my-profile"
Cypher --vpn off
Cypher vpn status
Cypher vpn countries
Cypher vpn disconnect
Cypher vpn reconnect
Cypher ip status
Cypher ip rotate --dry-run
Cypher ip rotate
Cypher ip leak-test
```

IP rotation switches between installed OpenVPN profiles and requires an active real tunnel.
It reports whether the observed public IPv4 changed; it cannot force an ISP or VPN provider to
assign a different address. Leak diagnostics query ipify for public addresses and compare system
DNS settings with the active profile. The DNS comparison is a warning heuristic, not proof that
DNS traffic stayed in the tunnel.

For development only, `CYPHER_VPN_PROVIDER=mock` enables a simulated provider. Mock mode
does not create a VPN tunnel, encrypt traffic, change your public address, or change firewall rules.

### Malware scans and Downloads monitoring

Install ClamAV or YARA locally and make the executable available on `PATH`. ClamAV signatures
should be kept current. The included YARA rules are examples, not a complete antivirus engine.

```powershell
Cypher fscan --help
Cypher fscan
Cypher fscan --quick
Cypher fscan --full
Cypher fscan --path "C:\Users\you\Downloads"
Cypher fscan --usb
Cypher malware status
Cypher malware scan
Cypher malware scan "C:\Users\you\Downloads"
Cypher malware scan-machine
Cypher malware scan-machine --yes
Cypher malware stop <finding-id>
Cypher malware monitor start
Cypher malware monitor status
Cypher malware findings
Cypher quarantine list
Cypher quarantine isolate <finding-id>
Cypher quarantine restore <finding-id>
Cypher quarantine delete <finding-id>
Cypher malware monitor stop
```

`fscan` is the first local file-protection layer: it hashes files, checks the bundled local hash
lists, and reports explainable filename/location signals. It scans common user-risk folders by
default; `--full` visits mounted fixed drives and `--usb` visits mounted removable drives. Repeat
scans use a local SQLite hash cache, and `.guardignore` patterns are honored. This initial layer
does **not** yet verify digital signatures, inspect executable/script contents, or run YARA/PE
analysis; it is not an antivirus verdict and cannot establish that an unlisted file is safe.
`--format` accepts `json`, `md`, or `html`; `--verbose` prints evidence. Exit codes are 0 for no
findings, 1 for findings/partial scans, and 2 when the risk scorer reaches Dangerous.

Manual scans run when requested. The optional monitor scans completed files in your Downloads
folder and queues findings; it does not remove files automatically. Isolating, restoring, or
permanently deleting a file requires confirmation. Files are scanned locally and are not uploaded
by Cypher.

The whole-machine scan checks mounted local fixed/removable drives (not network shares), can take a
long time, and may be partial when files are inaccessible. It requires ClamAV or YARA. After
confirmation, ClamAV detections are moved to quarantine; heuristic YARA findings remain queued for
review. You can permanently delete quarantined files from the dashboard or with `quarantine delete`.
`malware stop <finding-id>` can stop a running process only when its executable path exactly matches
a finding. Cypher does not execute detected files; do not run suspected malware.

### Live reverse-shell shield

The shield monitors established connections using heuristics, then prompts when it detects
suspicious activity. Choose **Yes** to allow that endpoint for the current shield session. Choose
**No**, or do not respond within 30 seconds, to deny it. On denial, the shield attempts a scoped
Windows Firewall rule, terminates the process, and tries OpenVPN profile rotation if a real
connection and alternate profile are available.

```powershell
Cypher shield start
Cypher shield status
Cypher shield stop
Cypher shield startup install
Cypher shield startup status
Cypher shield startup uninstall
```

The installer registers the shield for this Windows user's sign-in. Detection occurs after a
connection is established, so some data may already have passed. Firewall rules may require
administrator rights. The shield can miss threats or prompt on legitimate connections.

### Theft protection

```powershell
Cypher theft arm
Cypher theft test
Cypher theft status
Cypher theft disarm
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
Cypher scan . --format json
Cypher scan --staged
Cypher redact .\notes.txt
Cypher explain <finding-id>
Cypher ask "How should I handle an exposed token?"
Cypher safe-run https://example.com/login
Cypher install-hook
```

The local source scanner checks for selected secret/PII patterns and risky code constructs; it is
heuristic and can produce false positives or miss vulnerabilities. `redact` writes a separate
`.redacted` file by default. `safe-run` checks URL-only risk indicators locally; it never opens or
contacts the URL. Its heuristics cannot establish that an unverified site is safe. The pre-commit
hook scans staged Git content and blocks a commit when it reports findings.

Recurring schedules use Windows Task Scheduler. Configure malware scans with
`Cypher malware schedule hourly`, `daily`, or `off`; configure IP rotation with
`Cypher ip schedule daily --at 03:00` or `off`. Use `Cypher ip history` to review
local rotation attempts and `Cypher ip stop` to remove its scheduled task. Trusted Wi-Fi
safe zones can be managed with `Cypher theft safe-zones add "Network name"`,
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
authentication, and maintain tested backups. A clean Cypher scan is not proof that a file
or machine is safe.
