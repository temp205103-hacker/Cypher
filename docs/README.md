# Cypher documentation

Implementation documentation will grow with each module.

- `theft test` is a safe, non-destructive simulation.
- Destructive actions require explicit approval.
- Evidence is encrypted at rest.
- Detection helps identify common patterns and does not guarantee 100% protection.
- Existing OpenVPN profiles are migrated to `%APPDATA%\Cypher\openvpn_profiles`.
- The reverse-shell shield runs as a background process and may terminate suspicious processes
  and create Windows Firewall rules.
- The installer registers a current-user Windows logon startup entry for the shield; detections
  prompt the user and default to deny after 30 seconds.
- On first install or first interactive launch, setup asks for the user's name and theft-alert
  email. It repeats only if either value is missing; location sharing still requires explicit
  consent, and actual email delivery requires sender credentials.
- Denial terminates the detected process, attempts a scoped firewall rule, and rotates only through
  an available real OpenVPN profile. Detection happens after connection establishment.
- IP rotation switches between installed OpenVPN profiles and reports observed public IPv4 change.
- IP leak diagnostics query ipify and compare system DNS settings with the active profile; DNS
  comparison is a warning heuristic, not proof that queries stayed inside the tunnel.
- Manual malware scans use locally installed ClamAV/YARA; the optional Downloads monitor queues
  detections for explicit review and never removes files automatically.
- The Downloads monitor is not a pre-execution blocker and does not intercept Windows Store installs.
- A confirmed theft event while theft protection is armed attempts to email the consented location
  and locks the Windows session; the user can unlock it with their normal Windows sign-in.
- Theft location alerts are addressed only to the configured alert email; without SMTP sender
  credentials, email delivery is simulated rather than sent.
- `theft test` remains non-destructive and does not lock the workstation.
- The project does not yet include a background theft-signal monitor, so this live-event handler
  must be connected to a detector before arming can trigger an automatic lock.
