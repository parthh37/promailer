# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

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
