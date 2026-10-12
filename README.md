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
5. **Apply**:
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
| `GET /api/v1/queue?limit=&offset=` | queue | list queued messages |
| `GET /api/v1/queue/{id}` | queue | queue entry with per-recipient status |
| `POST /api/v1/queue/{id}/retry` | queue | retry now |
| `POST /api/v1/queue/retry` | queue | retry everything now |
| `DELETE /api/v1/queue/{id}` | queue | delete without NDR |
| `GET /api/v1/stats` | queue | counters |
| `GET /api/v1/check/{domain}?ip=` | admin | deliverability report |
| `POST /api/v1/reload` | admin | reload configuration |

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

**Monitoring**: scrape `/metrics`; alert on `promailer_queue_size` and
`promailer_recipients_deferred` growth.

**Upgrades**: run the new installer. The service is stopped, the binary replaced and the service
restarted. The queue and configuration are preserved.

## Building from source

Requires Rust (stable) and, on Windows, the MSVC build tools.

```bash
cargo build --release
```

```bash
cargo test
```

The installer is built with [Inno Setup 6](https://jrsoftware.org/isinfo.php):
`ISCC.exe /DAppVersion=0.1.0 installer\promailer.iss`

## Releasing

Every release ships a Windows installer automatically:

1. bump `version` in `Cargo.toml` and add a `## [x.y.z]` section to `CHANGELOG.md`
2. commit, then tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`

The [Release workflow](.github/workflows/release.yml) then runs the tests on Windows, builds the
`Setup.exe` and portable zip, **installs the setup on a clean Windows runner, starts the service
and sends test mail through it**, and only then publishes the GitHub release with checksums.
