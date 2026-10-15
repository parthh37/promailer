# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Status icon, desktop shortcut and website (new)
- `promailer-tray.exe`: notification-area icon showing whether the service is running (colour
  badge, queue size and host name in the tooltip) with a menu to open the Manager, start/stop/
  restart the service, edit the configuration, open Event Viewer or Services, and report a
  problem. Starts at sign-in for every user; each user can turn that off from the menu.
- Setup.exe and the MSI add a Promailer Manager desktop shortcut and register the status icon
  (Setup tasks `desktopicon` and `tray`; MSI properties `DESKTOP_SHORTCUT` and `TRAY`).
- Executables carry the Promailer icon and version information.
- Project website on GitHub Pages (`site/`).

### Crash reports (new)
- Internal errors (panics) in the service, Manager and status icon are saved as crash reports
  with email/IP addresses, host and account names removed; the service also logs Event ID 1020.
- Promailer Manager lists them (banner, Help → Crash Reports) and opens a pre-filled GitHub
  issue for each. With `[crash_reports] github_token` set, the service files them itself: one
  issue per distinct bug, repeats as comments.
- API: `GET /api/v1/crashes`, `DELETE /api/v1/crashes/{id}` (admin).
- `promailer service restart`.

### Promailer Manager (new)
- Native desktop GUI (`promailer-manager.exe`) installed with a Start-menu shortcut, laid out
  like the IIS 6 SMTP manager: console tree, details pane and a virtual-server Properties sheet
  (General, Access, Messages, Delivery) that edits only the settings you change.
- Status (queue, throughput, bounce rate), queue browser with retry/delete, message search with
  per-message timelines, live delivery log, Domains, DKIM key management, DNS check, and a
  configuration file editor with validation.

### Server
- Message history: queue and delivery events recorded to `<data_dir>\history\*.jsonl` with
  retention (`[history]` section).
- New API endpoints: `stats/history`, `events`, `search`, `queue/{id}/headers`, `config` (get,
  validate, save with backup, conflict detection and hot reload); `queue` accepts a `q` filter.
- Queue entries record the decoded `Subject`.
- DKIM key management API: list keys with their DNS record and publication status, generate keys
  on the server (added to the configuration and hot-reloaded), remove keys.
- `/health` reports the server host name.

### Windows integration
- TLS certificates from the Windows certificate store: `[tls] thumbprint` (and optional `store`)
  selects a certificate in `LocalMachine\My`. Keys are used through CNG, so non-exportable,
  TPM- and HSM-backed keys work. Renewals made by AD CS auto-enrollment are followed automatically.
- `promailer cert list` shows store certificates with thumbprint, expiry and private-key availability.
- The TLS certificate (store or PEM) is re-read hourly; renewed certificates are used without a restart.
  `config check` shows the certificate's subject, thumbprint and validity.
- Windows Event Log: start, stop, reload, start-up failures, certificate problems and errors are written
  to the Application log (source "Promailer") with stable event IDs for SCOM and other monitoring tools.
  Start-up failures, including invalid configuration, now appear in the Event Log.
- MSI package for Group Policy, SCCM and Intune (`HOSTNAME`, `START_SERVICE` properties),
  built and smoke-tested with every release next to `Setup.exe`.
- Release binaries, `Setup.exe` and the MSI are Authenticode-signed once a signing certificate is configured.
- `promailer.exe` carries Windows version information.

### Reliability
- Subsystem supervision: if an SMTP listener, the delivery scheduler, the HTTP API, the pickup
  watcher or another background task stops or panics, Promailer shuts down gracefully and exits
  with an error so the Service Control Manager restarts it, instead of running without it.
- Hang watchdog: when the service stops responding, the process is ended (Event ID 1005) and
  restarted by the SCM. Machine sleep, VM pauses and debugger breaks are not treated as hangs.
- Panics are recorded in `promailer.log` and the Event Log; a panic in the service's main thread
  is reported as a failure (and restarted) instead of aborting without a status report.
- Setup.exe re-applies delayed auto-start and the restart-on-failure actions on upgrades.
- A history or pickup directory that cannot be created disables only that feature; it does not
  cause a restart loop.
- `promailer config init --hostname <name> --keep-existing`.

## [0.1.0] - 2026-10-13

First public release.

### SMTP server
- RFC 5321 server with SIZE, 8BITMIME, PIPELINING, ENHANCEDSTATUSCODES, SMTPUTF8.
- STARTTLS and implicit TLS (port 465) via rustls; STARTTLS command-injection protection.
- SMTP AUTH PLAIN/LOGIN with Argon2 password hashes, per-user sender-domain and IP restrictions, login tarpit.
- Multiple listeners (e.g. 25 for trusted apps, 587 for authenticated submission).

### IIS 6 SMTP parity
- Connection control (allow/deny lists, CIDR) and relay restrictions (by IP, by authentication).
- Message limits: size, session size, messages per connection, recipients per message, hop count.
- Delivery: retry intervals, expiration timeout, delay notification, NDRs with copy-to address.
- Smart host (with STARTTLS/implicit TLS and authentication), "attempt direct delivery first",
  masquerade domain, FQDN, reverse DNS lookup of clients.
- Pickup directory compatible with `System.Net.Mail` `SpecifiedPickupDirectory` (`X-Sender`/`X-Receiver`).
- Drop directory for local domains; Badmail directory with `.BAD`/`.BDR` files.
- Per-remote-domain rules (smart host, TLS policy, connection limit, IP pool).

### Delivery engine
- Crash-safe filesystem queue (fsync + atomic rename, recovery on start-up).
- MX resolution with RFC 7505 null-MX and implicit-MX handling, equal-preference load balancing.
- Global and per-domain connection limits, outbound connection reuse, pipelined RCPT.
- Opportunistic or required TLS with automatic plain-text fallback for broken TLS peers.
- Outbound IP pools with per-IP HELO names, round-robin rotation.
- RFC 3464 delivery status notifications; bounces of bounces go to badmail (no loops).

### Authentication & deliverability
- DKIM signing (RSA-SHA256, Ed25519-SHA256) selected by From: domain, signed once at enqueue.
- `promailer dkim generate` prints the DNS record to publish.
- `promailer check` reports rDNS/FCrDNS, HELO consistency, SPF evaluation for your IPs, DKIM key match,
  DMARC policy and MX.

### Operations
- Windows service with automatic restart on failure, delayed auto-start, pre-shutdown handling and
  hot reload (`promailer service reload` / `sc control Promailer paramchange`).
- HTTP API: JSON send (HTML, attachments, inline images, custom headers), raw send, queue
  list/inspect/retry/delete, statistics, Prometheus `/metrics`, DNS checks, reload.
- Rotating logs: service log, SMTP protocol transcript and per-attempt delivery log.
- Rate limits per IP, per user and per API key; queue-size back-pressure.
- Windows installer (service, PATH, firewall, optional IIS SMTP disable) and portable zip.
