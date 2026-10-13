# Promailer

**A modern, production-grade outbound SMTP server for Windows: the replacement for the IIS 6 SMTP service.**

Promailer is a single, dependency-free executable written in Rust. It accepts mail from your
applications (SMTP, Pickup directory or HTTP API), signs it with DKIM, queues it durably and
delivers it to the world with retries, bounce handling and full logging. It runs as a Windows
service and keeps every concept IIS 6 administrators already know.

- **Drop-in IIS 6 replacement**: same relay rules, retry/expiry settings, smart host, masquerade
  domain, Pickup / Drop / Badmail directories. Existing .NET apps using `SpecifiedPickupDirectory`
  keep working.
- **Deliverability built in**: DKIM signing, plus a checker for rDNS, SPF, DKIM and DMARC.
- **Fail-safe**: crash-safe queue, automatic service restart, graceful shutdown, no mail lost on restart.
- **Efficient**: async I/O, outbound connection reuse, DNS caching. A 7.5 MB executable using about
  20 MB of RAM and no CPU when idle.

---

## Contents

- [Install](#install)
- [Quick start](#quick-start)
- [Sending mail](#sending-mail)
- [DNS setup for deliverability](#dns-setup-for-deliverability)
- [IIS 6 SMTP feature mapping](#iis-6-smtp-feature-mapping)
- [Promailer Manager (GUI)](#promailer-manager-gui)
- [HTTP API](#http-api)
- [Operations](#operations)
- [Building from source](#building-from-source)
- [Releasing](#releasing)

## Install

Download `Promailer-<version>-x64-Setup.exe` from the [Releases](https://github.com/parthh37/promailer/releases) page and run it as Administrator.

The installer:

1. installs `promailer.exe` to `C:\Program Files\Promailer`
2. creates `C:\ProgramData\Promailer\promailer.toml` (never overwritten on upgrade)
3. registers the **Promailer** Windows service (auto-start, restart on failure)
4. optionally adds Promailer to `PATH`, opens firewall ports and disables the IIS SMTP service

Data lives in `C:\ProgramData\Promailer` (access restricted to Administrators and SYSTEM):

| Folder     | Purpose                                                        |
|------------|----------------------------------------------------------------|
| `queue\`   | queued messages (`.eml`) and their delivery state (`.json`)    |
| `pickup\`  | drop `.eml` files here to send them                            |
| `drop\`    | mail for `local_domains`                                       |
| `badmail\` | undeliverable bounces and rejected pickup files (`.BAD`/`.BDR`)|
| `logs\`    | `promailer.*.log`, `smtp.*.log`, `delivery.*.log`              |

Silent install: `Promailer-x.y.z-x64-Setup.exe /VERYSILENT /TASKS="service,service\start,path"`

A portable zip is also published for manual deployments.

### MSI (Group Policy, SCCM, Intune)

`Promailer-<version>-x64.msi` installs the same files, service and data folder for managed
deployment:

```bat
msiexec /i Promailer-x.y.z-x64.msi /qn HOSTNAME=mail.example.com
```

| Property        | Default        | Meaning                                                           |
|-----------------|----------------|-------------------------------------------------------------------|
| `HOSTNAME`      | computer name  | `server.hostname` for a newly created `promailer.toml`            |
| `START_SERVICE` | `1`            | `0` installs the service without starting it                      |

For Group Policy, set properties with an MST transform. The configuration is created only if
missing and is never modified, repaired or removed by the MSI. Upgrades are major upgrades:
deploy the new MSI over the old one. A service that fails to start (for example, because port 25
is still used by IIS SMTP) does not roll back the installation; the reason is logged as Event
ID 1004. Firewall rules are not created by the MSI; manage them with Group Policy.

Use either the MSI or `Setup.exe` on a machine, not both. Each refuses to install over the other.

## Quick start

```bash
promailer config check
```

1. **Set the host name**: edit `server.hostname` in `promailer.toml` to a name like
   `mail.example.com` that matches the reverse DNS (PTR) of your public IP.
2. **Allow your applications**: add their IPs to `access.relay_allow`, or create an SMTP user:
   ```bash
   promailer user hash-password
   ```
3. **Enable DKIM** for each sending domain:
   ```bash
   promailer dkim generate --domain example.com --selector s1 --out "C:\ProgramData\Promailer\dkim"
   ```
   Publish the printed TXT record and paste the printed `[[dkim]]` block into the config.
4. **Verify DNS**:
   ```bash
   promailer check --domain example.com
   ```
5. **Enable TLS** (optional, for STARTTLS on port 587 / implicit TLS on 465) with a certificate
   from the Windows certificate store, the same one IIS would use:
   ```bash
   promailer cert list
   ```
   Copy the thumbprint of a valid certificate with `key = yes` into the config. Pasting from
   certlm.msc works as is: spaces and hidden characters are ignored.
   ```toml
   [tls]
   thumbprint = "3A1F00B2C4D5E6F708192A3B4C5D6E7F8091A2B3"
   # store = "WebHosting"    # default "My" (Personal); always LocalMachine
   ```
   Non-exportable, TPM- and HSM-backed keys work, since the key never leaves Windows. If the service
   runs as an account other than LocalSystem, grant it Read access in certlm.msc (All Tasks >
   Manage Private Keys). PEM files (`cert`/`key`) remain supported.
6. **Apply**:
   ```bash
   promailer service reload
   ```

## Sending mail

**SMTP** (any language or app): server `localhost`, port `25`. Use port 587 with STARTTLS and
AUTH for remote applications (see the commented listener in the config).

**.NET Pickup directory**: no network needed:

```csharp
var client = new SmtpClient {
    DeliveryMethod = SmtpDeliveryMethod.SpecifiedPickupDirectory,
    PickupDirectoryLocation = @"C:\ProgramData\Promailer\pickup"
};
client.Send(message);
```

**HTTP API**:

```bash
promailer api-key generate --name webapp
```

```bash
curl -X POST http://127.0.0.1:8025/api/v1/messages -H "Authorization: Bearer pm_..." -H "Content-Type: application/json" -d "{\"from\":\"Shop <orders@example.com>\",\"to\":[\"customer@gmail.com\"],\"subject\":\"Your order\",\"html\":\"<h1>Thanks!</h1>\",\"text\":\"Thanks!\"}"
```

## DNS setup for deliverability

Gmail, Outlook and Yahoo require all of the following for reliable inbox placement. `promailer check`
verifies each one and tells you exactly what to publish.

| Record | Where | Example |
|--------|-------|---------|
| **PTR (rDNS)** | set by your hosting provider / ISP | `203.0.113.10 → mail.example.com` |
| **A** | your DNS | `mail.example.com → 203.0.113.10` |
| **SPF** | TXT on `example.com` | `v=spf1 ip4:203.0.113.10 ~all` |
| **DKIM** | TXT on `s1._domainkey.example.com` | printed by `promailer dkim generate` |
| **DMARC** | TXT on `_dmarc.example.com` | `v=DMARC1; p=none; rua=mailto:dmarc@example.com` |

Also make sure your provider allows **outbound TCP port 25**. Many cloud providers block it by
default; if yours does, configure `[delivery.smarthost]`.

## IIS 6 SMTP feature mapping

| IIS 6 setting | Promailer |
|---|---|
| IP address / TCP port | `[[listener]] bind` |
| Limit number of connections / Connection time-out | `limits.max_connections`, `limits.command_timeout` |
| Enable logging (W3C) | `logging.protocol_log` (`smtp.*.log`) + `delivery.*.log` |
| Anonymous access / Basic authentication / Requires TLS | `listener.require_auth`, `[[user]]`, `listener.require_tls` |
| Secure communication > Certificate | `[tls] thumbprint` (Windows certificate store) or `[tls] cert`/`key` (PEM) |
| Connection control (grant/deny list) | `access.default`, `access.allow`, `access.deny` |
| Relay restrictions + "allow authenticated to relay" | `access.relay_allow`, `access.relay_authenticated` |
| Limit message size / session size | `limits.max_message_size`, `limits.max_session_size` |
| Limit messages per connection / recipients per message | `limits.max_messages_per_connection`, `limits.max_recipients_per_message` |
| Send copy of NDR to | `delivery.ndr_copy_to` |
| Badmail directory | `badmail\` (`.BAD` + `.BDR`) |
| Outbound retry intervals | `delivery.retry_intervals` |
| Delay notification / Expiration timeout | `delivery.delay_notification_after`, `delivery.expire_after` |
| Outbound security (TLS, smart host auth) | `delivery.tls`, `[delivery.smarthost]` |
| Limit outbound connections / per domain | `delivery.max_connections`, `delivery.max_connections_per_domain` |
| Maximum hop count | `server.max_hop_count` |
| Masquerade domain | `server.masquerade_domain` |
| Fully-qualified domain name | `server.hostname` |
| Smart host / attempt direct delivery first | `[delivery.smarthost]`, `delivery.attempt_direct_before_smarthost` |
| Perform reverse DNS lookup on incoming messages | `access.reverse_dns_lookup` |
| Pickup / Drop / Queue directories | `pickup\`, `drop\`, `queue\` |
| Remote domains (per-domain smart host, TLS) | `[[domain]]` |
| Local domains | `server.local_domains` |

**Beyond IIS:** DKIM signing, deliverability checker, HTTP API, rate limits, outbound IP pools,
connection reuse, Prometheus metrics, hot configuration reload, crash-safe queue.

## Promailer Manager (GUI)

`promailer-manager.exe` is a native desktop app installed alongside the service (Start menu →
Promailer → Promailer Manager). It is laid out like the IIS 6 SMTP manager: a console tree on the
left, a details pane on the right, and a **Properties** sheet for the virtual server. It talks to
the service over the HTTP API, so it can manage the local server or a remote one, and never runs
inside the mail flow.

**SMTP Virtual Server → Properties** (toolbar, Action menu, or double-click the node) has the
familiar IIS tabs. Settings are edited in forms; only the settings you change are written to
`promailer.toml`, so its comments and layout are kept:

| Tab | Settings |
|---|---|
| General | IP addresses and ports (listeners, encryption, require authentication), connection limit and time-out, logging |
| Access | connection control (granted/denied lists), relay restrictions, reverse DNS lookup, SMTP AUTH users (passwords are hashed in the Manager and never sent in clear) |
| Messages | message/session size, messages per connection, recipients per message, queue limit, non-delivery reports |
| Delivery | retry intervals, expiration, delay notification, outbound TLS, outbound connections, FQDN, masquerade domain, hop count, smart host |

| Tree node | What it does |
|---|---|
| Status | state, queue, throughput, delivered / deferred / bounced and bounce rate over 15 min – 24 h, with a chart |
| Queue | browse and filter queued messages, per-recipient status and last remote response, headers, retry or delete (single or bulk), retry all |
| Message Search | find messages by recipient, sender, subject, queue ID or remote response across the queue and the message history; per-message timeline |
| Delivery Log | live delivery events (queued, sent, deferred, bounced, expired, deleted, NDR) with filters |
| Domains | local domains (Drop folder) and remote-domain rules (smart host, TLS policy, connection limit) |
| DKIM Keys | create RSA/Ed25519 keys (generated on the server; the private key never leaves it), show the TXT record to publish, verify it is published, remove keys |
| DNS Check | rDNS/FCrDNS, HELO, SPF, DKIM, DMARC and MX report for a sending domain |
| Configuration File | edit `promailer.toml` directly with syntax highlighting and full validation |

Every change is validated exactly as a reload would validate it, the previous file is kept in
`config-backups\`, and the service reloads without dropping connections.

**Connecting**: create a key and give it the `admin` permission (`queue` is enough for read-only
monitoring; the configuration editor and DNS check need `admin`):

```
promailer api-key generate --name manager
```

Add the printed `[[api.keys]]` block to `promailer.toml` with `permissions = ["admin"]`, run
`promailer service reload`, then enter `http://127.0.0.1:8025` and the key in the Manager's
connection dialog. To manage a remote server, bind the API to a reachable address and restrict it
with `api.allow`. The API is plain HTTP, so use it across trusted networks only (or put it behind a
TLS reverse proxy).

The Manager renders with Direct3D 12 and falls back to Windows' built-in software renderer, so it
works on GPU-less servers over Remote Desktop. If it doesn't start, run
`promailer-manager.exe --opengl`.

## HTTP API

Authenticate with `Authorization: Bearer <key>` or `X-API-Key: <key>`. Permissions per key:
`send`, `queue`, `admin`. The API listens on `127.0.0.1:8025` by default and can be restricted by
`api.allow`.

| Method & path | Permission | Description |
|---|---|---|
| `GET /health` | - | liveness / version / queue size |
| `GET /metrics` | (`api.allow`) | Prometheus metrics |
| `POST /api/v1/messages` | send | send JSON message (see below) |
| `POST /api/v1/messages/raw` | send | send a raw RFC 5322 message `{from?, to?, raw \| raw_base64}` |
| `GET /api/v1/queue?limit=&offset=&q=` | queue | list queued messages, optionally filtered |
| `GET /api/v1/queue/{id}` | queue | queue entry with per-recipient status |
| `GET /api/v1/queue/{id}/headers` | queue | header block of a queued message |
| `POST /api/v1/queue/{id}/retry` | queue | retry now |
| `POST /api/v1/queue/retry` | queue | retry everything now |
| `DELETE /api/v1/queue/{id}` | queue | delete without NDR |
| `GET /api/v1/stats` | queue | counters |
| `GET /api/v1/stats/history?since=` | queue | 10-second samples of counters and queue size (last 24 h) |
| `GET /api/v1/events?after=&limit=` | queue | live event feed; pass the returned `last_seq` as `after` |
| `GET /api/v1/search?q=&kind=&days=&limit=` | queue | search the queue and message history |
| `GET /api/v1/check/{domain}?ip=` | admin | deliverability report |
| `POST /api/v1/reload` | admin | reload configuration |
| `GET /api/v1/config` | admin | configuration file text, path and SHA-256 |
| `POST /api/v1/config/validate` | admin | validate `{text}` without applying it |
| `PUT /api/v1/config` | admin | validate, back up, save and reload `{text, base_sha256}`; `409` if the file changed since it was read |
| `GET /api/v1/dkim` | admin | configured DKIM keys with the TXT record to publish and whether DNS matches |
| `POST /api/v1/dkim` | admin | generate a key on the server and add it to the configuration `{domain, selector, algorithm?, bits?, include_subdomains?}` |
| `DELETE /api/v1/dkim/{domain}/{selector}` | admin | remove a key from the configuration (the key file is kept) |

JSON send body:

```json
{
  "from": "Shop <orders@example.com>",
  "to": ["a@example.org"], "cc": [], "bcc": [],
  "reply_to": "support@example.com",
  "subject": "Your order",
  "text": "plain text part",
  "html": "<p>HTML part <img src=\"cid:logo\"></p>",
  "headers": { "List-Unsubscribe": "<mailto:unsub@example.com>" },
  "attachments": [
    { "filename": "invoice.pdf", "content": "<base64>" },
    { "filename": "logo.png", "content": "<base64>", "content_id": "logo" }
  ],
  "envelope_from": "bounces@example.com",
  "pool": "default"
}
```

Response: `202 {"id": "01J...", "status": "queued", "recipients": 1}`

## Operations

| Task | Command |
|---|---|
| Validate configuration | `promailer config check` |
| Apply configuration changes | `promailer service reload` |
| Start / stop | `promailer service start` / `promailer service stop` |
| Run in console (debugging) | `promailer run` |
| Inspect queue | `promailer queue list`, `promailer queue show <id>` |
| Deliverability report | `promailer check --domain example.com --ip 203.0.113.10` |

Listener, logging and `data_dir` changes need a service restart; everything else
(access lists, users, limits, delivery rules, DKIM keys, TLS certificates) reloads live.

**Logs**: `delivery.*.log` has one line per attempt:

```
01J9...  from=<orders@example.com> to=<a@gmail.com> status=sent attempt=1 relay=gmail-smtp-in.l.google.com [142.250.x.x] delay=1s response="250 2.0.0 OK ..."
```

**History**: every queue/delivery event is also written to `history\YYYY-MM-DD.jsonl` (one JSON
object per line, kept for `history.retention_days`). This is what message search reads.

**Monitoring**: scrape `/metrics`; alert on `promailer_queue_size` and
`promailer_recipients_deferred` growth.

**Windows Event Log**: the service writes to the **Application** log, source **Promailer**,
so SCOM and other monitoring tools can alert on it (disable with `[logging] event_log = false`).
Event IDs are stable:

| ID   | Level       | Meaning                                                                 |
|------|-------------|-------------------------------------------------------------------------|
| 1000 | Information | Service started (version, host name, listeners, TLS certificate)        |
| 1001 | Information | Service stopped                                                         |
| 1002 | Information | Configuration reloaded                                                  |
| 1003 | Error       | Configuration reload failed; the previous configuration stays active    |
| 1004 | Error       | Service could not start or stopped because of an error                  |
| 1010 | Warning     | TLS certificate expires soon (checked at load and daily)                |
| 1011 | Error       | TLS certificate in use is not valid (e.g. expired)                      |
| 1012 | Information | A different TLS certificate is now in use (renewal picked up)           |
| 1100 | Error       | Any other error (at most 20 per 10 minutes)                             |
| 1199 | Warning     | Error limit reached; further errors only go to `promailer.log`          |

Routine warnings caused by remote clients (failed logins, relay attempts) stay in the log files.

**TLS certificates**: Promailer re-reads the configured certificate every hour. Renewed PEM files
(e.g. from win-acme) and certificates renewed in the Windows certificate store (AD CS
auto-enrollment) are picked up without a restart.

**Upgrades**: run the new installer. The service is stopped, the binary replaced and the service
restarted. The queue and configuration are preserved.

## Building from source

Requires Rust (stable) and, on Windows, the MSVC build tools.

```bash
cargo build --workspace --release
```

```bash
cargo test --workspace
```

This builds both `promailer` (the service) and `promailer-manager` (the GUI, in `manager/`).

The installer is built with [Inno Setup 6](https://jrsoftware.org/isinfo.php):
`ISCC.exe /DAppVersion=0.1.0 installer\promailer.iss`

The MSI is built with [WiX Toolset 5](https://wixtoolset.org/) (`dotnet tool install --global wix --version 5.0.2`):
`wix build -arch x64 -d Version=0.1.0 installer\promailer.wxs -o dist\Promailer-0.1.0-x64.msi`

Windows-only code can be type-checked from macOS or Linux with
[cargo-xwin](https://github.com/rust-cross/cargo-xwin) (needs LLVM's `clang-cl`, `lld-link` and `llvm-lib`):
`cargo xwin clippy --target x86_64-pc-windows-msvc --all-targets`

## Releasing

Every release ships a Windows installer automatically:

1. bump `version` in `Cargo.toml` and add a `## [x.y.z]` section to `CHANGELOG.md`
2. commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`

The [Release workflow](.github/workflows/release.yml) then runs the tests on Windows, builds the
`Setup.exe`, MSI and portable zip, **installs both installers on a clean Windows runner, starts the
service and sends test mail through it** (including STARTTLS with Windows-store certificates and
Event Log checks), and only then publishes the GitHub release with checksums.

**Code signing** turns on automatically once these repository settings exist; until then releases
are unsigned:

| Setting                   | Kind     | Value                                                      |
|---------------------------|----------|------------------------------------------------------------|
| `SIGNING_CERT_PFX_BASE64` | secret   | `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))` |
| `SIGNING_CERT_PASSWORD`   | secret   | the .pfx password                                           |
| `SIGNING_TIMESTAMP_URL`   | variable | optional RFC 3161 server (default `http://timestamp.digicert.com`) |

`promailer.exe` is signed before it is packaged, so the installed binary, `Setup.exe`, its
uninstaller and the MSI all carry signatures.
