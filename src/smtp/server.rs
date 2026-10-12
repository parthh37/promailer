//! Inbound SMTP (submission / relay) server.
//!
//! Implements RFC 5321 with ESMTP extensions SIZE, 8BITMIME, PIPELINING,
//! ENHANCEDSTATUSCODES, SMTPUTF8, STARTTLS (RFC 3207) and AUTH PLAIN/LOGIN
//! (RFC 4954). Relay authorisation follows IIS semantics.

use super::{read_line, LineError};
use crate::access::{self, canonical_ip, ConnectDecision, SlotError};
use crate::app::App;
use crate::config::{Config, ListenerConfig, ListenerTls, UserConfig};
use crate::logging::PROTOCOL_TARGET;
use crate::message;
use crate::queue::{NewMessage, Source};
use crate::stats::Stats;
use crate::tls::Stream;
use base64::Engine;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

const MAX_COMMAND_LINE: usize = 4096;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_AUTH_FAILURES: u32 = 3;

pub async fn serve(app: Arc<App>, listener: TcpListener, lcfg: ListenerConfig) {
    let lcfg = Arc::new(lcfg);
    let mut shutdown = app.shutdown_rx();
    info!(listener = %lcfg.name, bind = %lcfg.bind, tls = ?lcfg.tls, "SMTP listener started");
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            res = listener.accept() => match res {
                Ok((sock, peer)) => {
                    let app = app.clone();
                    let lcfg = lcfg.clone();
                    tokio::spawn(async move {
                        handle_connection(app, lcfg, sock, peer).await;
                    });
                }
                Err(e) => {
                    // EMFILE/ENOBUFS etc. Back off briefly instead of spinning.
                    warn!(listener = %lcfg.name, error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }
    info!(listener = %lcfg.name, "SMTP listener stopped");
}

async fn reject_and_close(mut sock: TcpStream, line: &str) {
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let _ = sock.write_all(line.as_bytes()).await;
        let _ = sock.shutdown().await;
    })
    .await;
}

async fn handle_connection(app: Arc<App>, lcfg: Arc<ListenerConfig>, sock: TcpStream, peer: SocketAddr) {
    let cfg = app.cfg();
    let ip = canonical_ip(peer.ip());
    let _ = sock.set_nodelay(true);
    Stats::inc(&app.stats.connections_total);

    if access::connection_allowed(&cfg.access, ip) == ConnectDecision::Deny {
        Stats::inc(&app.stats.connections_rejected);
        info!(target: PROTOCOL_TARGET, "- {ip} connection denied by access control");
        reject_and_close(sock, "554 5.7.1 Access denied\r\n").await;
        return;
    }
    if !app.rate_conn.check(&ip, cfg.limits.connections_per_minute_per_ip) {
        Stats::inc(&app.stats.connections_rejected);
        reject_and_close(sock, "421 4.7.0 Too many connections, try again later\r\n").await;
        return;
    }
    let _slot = match app.connections.try_acquire(ip, cfg.limits.max_connections, cfg.limits.max_connections_per_ip) {
        Ok(s) => s,
        Err(e) => {
            Stats::inc(&app.stats.connections_rejected);
            let msg = match e {
                SlotError::TooManyTotal => "421 4.3.2 Server busy, try again later\r\n",
                SlotError::TooManyFromIp => "421 4.7.0 Too many connections from your IP\r\n",
            };
            reject_and_close(sock, msg).await;
            return;
        }
    };

    let mut stream = Stream::Plain(sock);
    if lcfg.tls == ListenerTls::Implicit {
        let Some(acceptor) = app.tls_acceptor.load_full().as_ref().clone() else {
            warn!("implicit TLS listener without certificate");
            return;
        };
        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, stream.upgrade_server(&acceptor)).await {
            Ok(Ok(s)) => stream = s,
            Ok(Err(e)) => {
                debug!(%ip, error = %e, "TLS handshake failed");
                return;
            }
            Err(_) => return,
        }
    }

    let mut ptr = None;
    if cfg.access.reverse_dns_lookup {
        ptr = tokio::time::timeout(Duration::from_secs(5), app.dns.ptr(ip))
            .await
            .ok()
            .and_then(|r| r.ok())
            .and_then(|v| v.into_iter().next());
        if ptr.is_none() && cfg.access.require_reverse_dns {
            Stats::inc(&app.stats.connections_rejected);
            if let Stream::Plain(s) = stream {
                reject_and_close(s, "550 5.7.25 Reverse DNS validation failed\r\n").await;
            }
            return;
        }
    }

    let id = ulid::Ulid::new().to_string();
    let mut session = Session {
        app: app.clone(),
        cfg: cfg.clone(),
        lcfg,
        id,
        ip,
        ptr,
        helo: None,
        esmtp: false,
        tls_info: stream.tls_info(),
        auth_user: None,
        auth_failures: 0,
        tx: Transaction::default(),
        messages: 0,
        session_bytes: 0,
        errors: 0,
    };
    let mut conn = Conn { reader: BufReader::with_capacity(8192, stream), out: Vec::with_capacity(512) };
    info!(target: PROTOCOL_TARGET, "{} {} connected (tls={})", session.id, ip, session.tls_info.is_some());
    let res = tokio::time::timeout(cfg.limits.session_timeout, session.run(&mut conn)).await;
    if res.is_err() {
        let _ = conn.send("421 4.4.2 Session time limit exceeded").await;
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), conn.reader.get_mut().shutdown()).await;
    info!(target: PROTOCOL_TARGET, "{} {} disconnected", session.id, ip);
}

struct Conn {
    reader: BufReader<Stream>,
    out: Vec<u8>,
}

impl Conn {
    fn queue(&mut self, line: &str) {
        self.out.extend_from_slice(line.as_bytes());
        self.out.extend_from_slice(b"\r\n");
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        if !self.out.is_empty() {
            let out = std::mem::take(&mut self.out);
            let w = self.reader.get_mut();
            tokio::time::timeout(Duration::from_secs(60), async {
                w.write_all(&out).await?;
                w.flush().await
            })
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))??;
            self.out = out;
            self.out.clear();
        }
        Ok(())
    }

    async fn send(&mut self, line: &str) -> std::io::Result<()> {
        self.queue(line);
        self.flush().await
    }

    /// With PIPELINING, replies are batched until the client's input is drained.
    async fn flush_if_idle(&mut self) -> std::io::Result<()> {
        if self.reader.buffer().is_empty() {
            self.flush().await
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct Transaction {
    mail_from: Option<String>,
    rcpts: Vec<String>,
    declared_size: usize,
}

struct Session {
    app: Arc<App>,
    cfg: Arc<Config>,
    lcfg: Arc<ListenerConfig>,
    id: String,
    ip: IpAddr,
    ptr: Option<String>,
    helo: Option<String>,
    esmtp: bool,
    tls_info: Option<String>,
    auth_user: Option<Arc<UserConfig>>,
    auth_failures: u32,
    tx: Transaction,
    messages: usize,
    session_bytes: u64,
    errors: usize,
}

enum Flow {
    Continue,
    Close,
}

impl Session {
    fn log_in(&self, line: &str) {
        info!(target: PROTOCOL_TARGET, "{} {} > {}", self.id, self.ip, line);
    }

    fn reply(&self, conn: &mut Conn, line: &str) {
        info!(target: PROTOCOL_TARGET, "{} {} < {}", self.id, self.ip, line);
        conn.queue(line);
    }

    fn reply_multi(&self, conn: &mut Conn, code: u16, lines: &[String]) {
        for (i, l) in lines.iter().enumerate() {
            let sep = if i + 1 == lines.len() { ' ' } else { '-' };
            self.reply(conn, &format!("{code}{sep}{l}"));
        }
    }

    fn tls_available(&self) -> bool {
        self.lcfg.tls == ListenerTls::Starttls && self.tls_info.is_none() && self.app.tls_acceptor.load().is_some()
    }

    fn auth_available(&self) -> bool {
        !self.cfg.users.is_empty()
            && self.auth_user.is_none()
            && (self.tls_info.is_some() || self.lcfg.allow_plaintext_auth)
    }

    fn hostname(&self) -> &str {
        &self.cfg.server.hostname
    }

    async fn run(&mut self, conn: &mut Conn) {
        let banner = self.lcfg.banner.clone().unwrap_or_else(|| "ESMTP Promailer ready".into());
        self.reply(conn, &format!("220 {} {}", self.hostname(), banner));
        if conn.flush().await.is_err() {
            return;
        }

        let mut line = Vec::with_capacity(256);
        loop {
            let read = tokio::time::timeout(
                self.cfg.limits.command_timeout,
                read_line(&mut conn.reader, &mut line, MAX_COMMAND_LINE),
            )
            .await;
            match read {
                Err(_) => {
                    self.reply(conn, &format!("421 4.4.2 {} Error: timeout exceeded", self.hostname()));
                    let _ = conn.flush().await;
                    return;
                }
                Ok(Err(LineError::Eof)) | Ok(Err(LineError::Io(_))) => return,
                Ok(Err(LineError::TooLong)) => {
                    self.reply(conn, "500 5.5.2 Line too long");
                    if self.bump_error(conn) {
                        let _ = conn.flush().await;
                        return;
                    }
                }
                Ok(Ok(())) => {
                    let text = String::from_utf8_lossy(&line).trim_end_matches(['\r', '\n']).to_string();
                    match self.dispatch(conn, &text).await {
                        Flow::Continue => {}
                        Flow::Close => {
                            let _ = conn.flush().await;
                            return;
                        }
                    }
                }
            }
            if conn.flush_if_idle().await.is_err() {
                return;
            }
        }
    }

    /// Returns true when the error budget is exhausted (caller should close).
    fn bump_error(&mut self, conn: &mut Conn) -> bool {
        self.errors += 1;
        if self.errors >= self.cfg.limits.max_errors_per_session.max(1) {
            self.reply(conn, "421 4.7.0 Too many errors, closing connection");
            return true;
        }
        false
    }

    async fn dispatch(&mut self, conn: &mut Conn, text: &str) -> Flow {
        let (verb, args) = match text.split_once(' ') {
            Some((v, a)) => (v.to_ascii_uppercase(), a.trim()),
            None => (text.to_ascii_uppercase(), ""),
        };
        if verb == "AUTH" {
            self.log_in(&format!("AUTH {}", args.split_whitespace().next().unwrap_or("")));
        } else {
            self.log_in(text);
        }

        if self.app.is_shutting_down() && verb != "QUIT" {
            self.reply(conn, "421 4.3.2 Service shutting down, try again later");
            return Flow::Close;
        }

        match verb.as_str() {
            "EHLO" => self.cmd_helo(conn, args, true),
            "HELO" => self.cmd_helo(conn, args, false),
            "STARTTLS" => return self.cmd_starttls(conn, args).await,
            "AUTH" => return self.cmd_auth(conn, args).await,
            "MAIL" => self.cmd_mail(conn, args),
            "RCPT" => self.cmd_rcpt(conn, args),
            "DATA" => return self.cmd_data(conn, args).await,
            "RSET" => {
                self.tx = Transaction::default();
                self.reply(conn, "250 2.0.0 OK");
            }
            "NOOP" => self.reply(conn, "250 2.0.0 OK"),
            "QUIT" => {
                self.reply(conn, &format!("221 2.0.0 {} closing connection", self.hostname()));
                return Flow::Close;
            }
            "VRFY" => self.reply(conn, "252 2.5.2 Cannot VRFY user, but will accept message"),
            "EXPN" => self.reply(conn, "502 5.5.1 EXPN not available"),
            "HELP" => {
                self.reply(conn, "214 2.0.0 Commands: HELO EHLO STARTTLS AUTH MAIL RCPT DATA RSET NOOP QUIT VRFY")
            }
            // Cross-protocol attempts (HTTP to port 25, etc.)
            "GET" | "POST" | "PUT" | "HEAD" | "CONNECT" | "USER" => {
                warn!(ip = %self.ip, verb = %verb, "non-SMTP protocol detected, closing");
                return Flow::Close;
            }
            _ => {
                self.reply(conn, "500 5.5.2 Command unrecognized");
                if self.bump_error(conn) {
                    return Flow::Close;
                }
            }
        }
        Flow::Continue
    }

    fn cmd_helo(&mut self, conn: &mut Conn, args: &str, esmtp: bool) {
        let name = args.split_whitespace().next().unwrap_or("");
        if name.is_empty() {
            self.reply(conn, &format!("501 5.5.4 Syntax: {} hostname", if esmtp { "EHLO" } else { "HELO" }));
            return;
        }
        self.helo = Some(name.chars().take(255).collect());
        self.esmtp = esmtp;
        self.tx = Transaction::default();
        if !esmtp {
            self.reply(conn, &format!("250 {} Hello [{}]", self.hostname(), self.ip));
            return;
        }
        let mut lines = vec![
            format!("{} Hello {} [{}]", self.hostname(), name, self.ip),
            format!("SIZE {}", self.cfg.limits.max_message_size.0),
            "8BITMIME".into(),
            "PIPELINING".into(),
            "ENHANCEDSTATUSCODES".into(),
            "SMTPUTF8".into(),
        ];
        if self.tls_available() {
            lines.push("STARTTLS".into());
        }
        if self.auth_available() {
            lines.push("AUTH PLAIN LOGIN".into());
            lines.push("AUTH=PLAIN LOGIN".into()); // legacy Outlook / old .NET clients
        }
        lines.push("HELP".into());
        self.reply_multi(conn, 250, &lines);
    }

    async fn cmd_starttls(&mut self, conn: &mut Conn, args: &str) -> Flow {
        if !args.is_empty() {
            self.reply(conn, "501 5.5.4 Syntax: STARTTLS");
            return Flow::Continue;
        }
        if !self.tls_available() {
            self.reply(conn, "454 4.7.0 TLS not available");
            return Flow::Continue;
        }
        let Some(acceptor) = self.app.tls_acceptor.load_full().as_ref().clone() else {
            self.reply(conn, "454 4.7.0 TLS not available");
            return Flow::Continue;
        };
        self.reply(conn, "220 2.0.0 Ready to start TLS");
        if conn.flush().await.is_err() {
            return Flow::Close;
        }
        // Swap the stream out; any plaintext the client pipelined after STARTTLS
        // sits in the BufReader buffer and is discarded here (CVE-2011-0411).
        let reader = std::mem::replace(&mut conn.reader, BufReader::new(Stream::Detached));
        let stream = reader.into_inner();
        match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, stream.upgrade_server(&acceptor)).await {
            Ok(Ok(tls)) => {
                self.tls_info = tls.tls_info();
                conn.reader = BufReader::with_capacity(8192, tls);
                info!(target: PROTOCOL_TARGET, "{} {} TLS established: {}", self.id, self.ip, self.tls_info.as_deref().unwrap_or(""));
                // RFC 3207: forget everything learned before TLS.
                self.helo = None;
                self.esmtp = false;
                self.tx = Transaction::default();
                Flow::Continue
            }
            Ok(Err(e)) => {
                debug!(ip = %self.ip, error = %e, "STARTTLS handshake failed");
                Flow::Close
            }
            Err(_) => Flow::Close,
        }
    }

    async fn read_auth_line(&self, conn: &mut Conn, prompt: &str) -> Option<String> {
        self.reply(conn, &format!("334 {prompt}"));
        conn.flush().await.ok()?;
        let mut buf = Vec::new();
        tokio::time::timeout(self.cfg.limits.command_timeout, read_line(&mut conn.reader, &mut buf, MAX_COMMAND_LINE))
            .await
            .ok()?
            .ok()?;
        Some(String::from_utf8_lossy(&buf).trim().to_string())
    }

    async fn cmd_auth(&mut self, conn: &mut Conn, args: &str) -> Flow {
        if self.helo.is_none() || !self.esmtp {
            self.reply(conn, "503 5.5.1 Error: send EHLO first");
            return Flow::Continue;
        }
        if self.auth_user.is_some() {
            self.reply(conn, "503 5.5.1 Error: already authenticated");
            return Flow::Continue;
        }
        if self.tx.mail_from.is_some() {
            self.reply(conn, "503 5.5.1 Error: AUTH not allowed during a mail transaction");
            return Flow::Continue;
        }
        if self.cfg.users.is_empty() {
            self.reply(conn, "502 5.5.1 Authentication not enabled");
            return Flow::Continue;
        }
        if self.tls_info.is_none() && !self.lcfg.allow_plaintext_auth {
            self.reply(conn, "538 5.7.11 Encryption required for requested authentication mechanism");
            return Flow::Continue;
        }

        let mut parts = args.split_whitespace();
        let mech = parts.next().unwrap_or("").to_ascii_uppercase();
        let initial = parts.next().map(|s| s.to_string());
        let b64 = base64::engine::general_purpose::STANDARD;
        let decode = |s: &str| b64.decode(s.trim()).ok().map(|v| String::from_utf8_lossy(&v).into_owned());

        let creds: Option<(String, String)> = match mech.as_str() {
            "PLAIN" => {
                let resp = match initial {
                    Some(i) if i != "=" => Some(i),
                    _ => self.read_auth_line(conn, "").await,
                };
                match resp {
                    Some(r) if r == "*" => {
                        self.reply(conn, "501 5.0.0 Authentication cancelled");
                        return Flow::Continue;
                    }
                    Some(r) => decode(&r).and_then(|s| {
                        let f: Vec<&str> = s.split('\0').collect();
                        (f.len() == 3).then(|| (f[1].to_string(), f[2].to_string()))
                    }),
                    None => return Flow::Close,
                }
            }
            "LOGIN" => {
                let user = match initial {
                    Some(i) => decode(&i),
                    None => match self.read_auth_line(conn, "VXNlcm5hbWU6").await {
                        Some(r) if r == "*" => {
                            self.reply(conn, "501 5.0.0 Authentication cancelled");
                            return Flow::Continue;
                        }
                        Some(r) => decode(&r),
                        None => return Flow::Close,
                    },
                };
                let pass = match self.read_auth_line(conn, "UGFzc3dvcmQ6").await {
                    Some(r) if r == "*" => {
                        self.reply(conn, "501 5.0.0 Authentication cancelled");
                        return Flow::Continue;
                    }
                    Some(r) => decode(&r),
                    None => return Flow::Close,
                };
                user.zip(pass)
            }
            _ => {
                self.reply(conn, "504 5.5.4 Unrecognized authentication type");
                return Flow::Continue;
            }
        };

        let Some((user, pass)) = creds else {
            self.reply(conn, "501 5.5.2 Cannot decode response");
            return Flow::Continue;
        };

        let account = self.cfg.users.iter().find(|u| u.username.eq_ignore_ascii_case(&user) && !u.disabled).cloned();
        let ok = match &account {
            Some(u) if !u.allowed_ips.is_empty() && !access::in_list(&u.allowed_ips, self.ip) => false,
            Some(u) => self.app.auth_cache.verify(&u.username, &pass, &u.password_hash).await,
            None => {
                // Burn comparable CPU time so valid usernames can't be discovered by timing.
                let _ = tokio::task::spawn_blocking(|| {
                    crate::auth::verify_password(
                        "x",
                        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$9nS3Ms4wDVgMvcJWQyX0xA",
                    )
                })
                .await;
                false
            }
        };

        if ok {
            let account = account.unwrap();
            info!(target: PROTOCOL_TARGET, "{} {} authenticated as {}", self.id, self.ip, account.username);
            Stats::inc(&self.app.stats.auth_success);
            self.auth_user = Some(Arc::new(account));
            self.reply(conn, "235 2.7.0 Authentication successful");
            Flow::Continue
        } else {
            Stats::inc(&self.app.stats.auth_failure);
            self.auth_failures += 1;
            warn!(ip = %self.ip, user = %user, "SMTP authentication failed");
            // Tarpit: slows brute-force attempts without holding a thread.
            tokio::time::sleep(Duration::from_secs(self.auth_failures as u64)).await;
            if self.auth_failures >= MAX_AUTH_FAILURES {
                self.reply(conn, "421 4.7.0 Too many authentication failures");
                return Flow::Close;
            }
            self.reply(conn, "535 5.7.8 Authentication credentials invalid");
            Flow::Continue
        }
    }

    fn cmd_mail(&mut self, conn: &mut Conn, args: &str) {
        if self.helo.is_none() {
            self.reply(conn, "503 5.5.1 Error: send HELO/EHLO first");
            return;
        }
        if self.tx.mail_from.is_some() {
            self.reply(conn, "503 5.5.1 Error: nested MAIL command");
            return;
        }
        if self.lcfg.require_tls && self.tls_info.is_none() {
            self.reply(conn, "530 5.7.0 Must issue a STARTTLS command first");
            return;
        }
        if self.lcfg.require_auth && self.auth_user.is_none() {
            self.reply(conn, "530 5.7.0 Authentication required");
            return;
        }
        if self.messages >= self.cfg.limits.max_messages_per_connection.max(1) {
            self.reply(conn, "452 4.5.3 Too many messages in this session, reconnect");
            return;
        }
        let max_q = self.cfg.limits.max_queue_size;
        if max_q > 0 && self.app.queue.len() >= max_q {
            self.reply(conn, "452 4.3.1 Insufficient system storage, try again later");
            return;
        }
        let Some((addr, params)) = parse_path(args, "FROM:") else {
            self.reply(conn, "501 5.5.4 Syntax: MAIL FROM:<address>");
            return;
        };
        if !addr.is_empty() && !message::valid_mailbox(&addr) {
            self.reply(conn, "501 5.1.7 Bad sender address syntax");
            return;
        }
        let max = self.cfg.limits.max_message_size.as_usize();
        let mut declared = 0usize;
        for p in params {
            let (k, v) = p.split_once('=').unwrap_or((p.as_str(), ""));
            match k.to_ascii_uppercase().as_str() {
                "SIZE" => {
                    declared = v.parse().unwrap_or(0);
                    if declared > max {
                        self.reply(conn, "552 5.3.4 Message size exceeds fixed maximum message size");
                        return;
                    }
                }
                "BODY" | "SMTPUTF8" | "AUTH" => {}
                _ => {
                    self.reply(conn, &format!("555 5.5.4 Unsupported parameter {k}"));
                    return;
                }
            }
        }
        if let Some(u) = &self.auth_user {
            if !u.allowed_sender_domains.is_empty() {
                let d = message::domain_of(&addr);
                if !u.allowed_sender_domains.iter().any(|a| a.eq_ignore_ascii_case(&d)) {
                    self.reply(conn, "553 5.7.1 Sender address rejected: not owned by authenticated user");
                    return;
                }
            }
            let limit = u.messages_per_minute.unwrap_or(self.cfg.limits.messages_per_minute_per_user);
            if !self.app.rate_user.check(&u.username.to_lowercase(), limit) {
                self.reply(conn, "450 4.7.1 Rate limit exceeded, try again later");
                return;
            }
        }
        if !self.app.rate_ip.check(&self.ip, self.cfg.limits.messages_per_minute_per_ip) {
            self.reply(conn, "450 4.7.1 Rate limit exceeded, try again later");
            return;
        }
        self.tx = Transaction { mail_from: Some(addr), rcpts: Vec::new(), declared_size: declared };
        self.reply(conn, "250 2.1.0 Sender OK");
    }

    fn relay_allowed(&self, domain: &str) -> bool {
        self.cfg.is_local_domain(domain)
            || (self.auth_user.is_some() && self.cfg.access.relay_authenticated)
            || access::in_list(&self.cfg.access.relay_allow, self.ip)
    }

    fn cmd_rcpt(&mut self, conn: &mut Conn, args: &str) {
        if self.tx.mail_from.is_none() {
            self.reply(conn, "503 5.5.1 Error: need MAIL command");
            return;
        }
        if self.tx.rcpts.len() >= self.cfg.limits.max_recipients_per_message.max(1) {
            self.reply(conn, "452 4.5.3 Too many recipients");
            return;
        }
        let Some((addr, params)) = parse_path(args, "TO:") else {
            self.reply(conn, "501 5.5.4 Syntax: RCPT TO:<address>");
            return;
        };
        if !message::valid_mailbox(&addr) {
            self.reply(conn, "501 5.1.3 Bad recipient address syntax");
            return;
        }
        for p in params {
            let k = p.split_once('=').map(|(k, _)| k).unwrap_or(&p).to_ascii_uppercase();
            if !matches!(k.as_str(), "NOTIFY" | "ORCPT") {
                self.reply(conn, &format!("555 5.5.4 Unsupported parameter {k}"));
                return;
            }
        }
        let domain = message::domain_of(&addr);
        if !self.relay_allowed(&domain) {
            warn!(ip = %self.ip, rcpt = %addr, "relay denied");
            self.reply(conn, &format!("550 5.7.1 Unable to relay for {addr}"));
            let _ = self.bump_error(conn);
            return;
        }
        self.tx.rcpts.push(addr);
        self.reply(conn, "250 2.1.5 Recipient OK");
    }

    async fn cmd_data(&mut self, conn: &mut Conn, args: &str) -> Flow {
        if !args.is_empty() {
            self.reply(conn, "501 5.5.4 Syntax: DATA");
            return Flow::Continue;
        }
        if self.tx.mail_from.is_none() {
            self.reply(conn, "503 5.5.1 Error: need MAIL command");
            return Flow::Continue;
        }
        if self.tx.rcpts.is_empty() {
            self.reply(conn, "554 5.5.1 Error: no valid recipients");
            return Flow::Continue;
        }
        self.reply(conn, "354 Start mail input; end with <CRLF>.<CRLF>");
        if conn.flush().await.is_err() {
            return Flow::Close;
        }

        let max_msg = self.cfg.limits.max_message_size.as_usize();
        let session_left = self.cfg.limits.max_session_size.0.saturating_sub(self.session_bytes) as usize;
        let limit = max_msg.min(session_left);
        let initial_cap = self.tx.declared_size.clamp(4096, limit.max(4096));
        let data =
            match tokio::time::timeout(self.cfg.limits.data_timeout, read_data(&mut conn.reader, limit, initial_cap))
                .await
            {
                Err(_) => {
                    self.reply(conn, "421 4.4.2 Error: timeout exceeded during DATA");
                    return Flow::Close;
                }
                Ok(Err(_)) => return Flow::Close,
                Ok(Ok(DataResult::TooBig)) => {
                    Stats::inc(&self.app.stats.messages_rejected);
                    self.tx = Transaction::default();
                    self.reply(conn, "552 5.3.4 Message size exceeds fixed maximum message size");
                    return Flow::Continue;
                }
                Ok(Ok(DataResult::Complete(d))) => d,
            };

        let hdrs = message::headers(&data);
        if message::count_received(&hdrs) >= self.cfg.server.max_hop_count {
            Stats::inc(&self.app.stats.messages_rejected);
            self.tx = Transaction::default();
            self.reply(conn, "554 5.4.6 Too many hops (mail loop?)");
            return Flow::Continue;
        }

        let tx = std::mem::take(&mut self.tx);
        let rcpt_hint = (tx.rcpts.len() == 1).then(|| tx.rcpts[0].as_str());
        let received = message::received_header(&message::ReceivedInfo {
            helo: self.helo.as_deref().unwrap_or("unknown"),
            client_ip: self.ip,
            client_ptr: self.ptr.as_deref(),
            hostname: self.hostname(),
            protocol: match (self.esmtp, self.tls_info.is_some(), self.auth_user.is_some()) {
                (false, _, _) => "SMTP",
                (true, false, false) => "ESMTP",
                (true, true, false) => "ESMTPS",
                (true, false, true) => "ESMTPA",
                (true, true, true) => "ESMTPSA",
            },
            tls: self.tls_info.as_deref(),
            id: &self.id,
            recipient: rcpt_hint,
            auth_user: self.auth_user.as_ref().map(|u| u.username.as_str()),
        });
        let mut full = Vec::with_capacity(received.len() + data.len());
        full.extend_from_slice(received.as_bytes());
        full.extend_from_slice(&data);
        drop(data);

        let size = full.len() as u64;
        let new = NewMessage {
            sender: tx.mail_from.unwrap_or_default(),
            recipients: tx.rcpts,
            data: full,
            source: Source::Smtp { ip: self.ip, user: self.auth_user.as_ref().map(|u| u.username.clone()) },
            pool: None,
        };
        match crate::queue::enqueue(&self.app, new).await {
            Ok(id) => {
                self.messages += 1;
                self.session_bytes += size;
                Stats::inc(&self.app.stats.messages_received);
                self.app.stats.bytes_received.fetch_add(size, std::sync::atomic::Ordering::Relaxed);
                self.reply(conn, &format!("250 2.6.0 Queued as {id}"));
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to queue message");
                self.reply(conn, "451 4.3.0 Error: queue file write error");
            }
        }
        Flow::Continue
    }
}

enum DataResult {
    Complete(Vec<u8>),
    TooBig,
}

/// Read the DATA payload: dot-unstuffing, CRLF normalisation and size limiting.
/// When the limit is exceeded the rest is drained (not stored) so a 552 can be
/// returned cleanly at the end of data instead of dropping the connection.
async fn read_data<R: tokio::io::AsyncBufRead + Unpin>(
    r: &mut R,
    limit: usize,
    initial_cap: usize,
) -> Result<DataResult, LineError> {
    let mut data = Vec::with_capacity(initial_cap);
    let mut line = Vec::with_capacity(1024);
    let mut too_big = false;
    loop {
        let max_line = if too_big { 1024 * 1024 } else { (limit - data.len()).saturating_add(1024) };
        match read_line(r, &mut line, max_line).await {
            Ok(()) => {}
            Err(LineError::TooLong) => {
                too_big = true;
                data = Vec::new();
                continue;
            }
            Err(e) => return Err(e),
        }
        if line == b".\r\n" || line == b".\n" {
            break;
        }
        if too_big {
            continue;
        }
        let content = if line.first() == Some(&b'.') { &line[1..] } else { &line[..] };
        let body = content.strip_suffix(b"\n").unwrap_or(content);
        let body = body.strip_suffix(b"\r").unwrap_or(body);
        if data.len() + body.len() + 2 > limit {
            too_big = true;
            data = Vec::new();
            continue;
        }
        data.extend_from_slice(body);
        data.extend_from_slice(b"\r\n");
    }
    Ok(if too_big { DataResult::TooBig } else { DataResult::Complete(data) })
}

/// Parse `FROM:<addr> PARAM=VAL ...` (tolerating a space after the colon and
/// missing angle brackets, as sent by some legacy applications).
fn parse_path(args: &str, prefix: &str) -> Option<(String, Vec<String>)> {
    if args.len() < prefix.len() || !args[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return None;
    }
    let rest = args[prefix.len()..].trim_start();
    let (addr, tail) = if let Some(stripped) = rest.strip_prefix('<') {
        let end = stripped.find('>')?;
        (&stripped[..end], &stripped[end + 1..])
    } else {
        match rest.split_once(' ') {
            Some((a, t)) => (a, t),
            None => (rest, ""),
        }
    };
    // Strip source routes: <@a,@b:user@c>
    let addr = addr.rsplit_once(':').map(|(_, a)| a).unwrap_or(addr).trim();
    let params = tail.split_whitespace().map(|s| s.to_string()).collect();
    Some((addr.to_string(), params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[test]
    fn path_parsing() {
        assert_eq!(parse_path("FROM:<a@b.com> SIZE=100", "FROM:"), Some(("a@b.com".into(), vec!["SIZE=100".into()])));
        assert_eq!(parse_path("from: <a@b.com>", "FROM:"), Some(("a@b.com".into(), vec![])));
        assert_eq!(parse_path("FROM:<>", "FROM:"), Some(("".into(), vec![])));
        assert_eq!(parse_path("TO:a@b.com", "TO:"), Some(("a@b.com".into(), vec![])));
        assert_eq!(parse_path("TO:<@relay.x:a@b.com>", "TO:"), Some(("a@b.com".into(), vec![])));
        assert_eq!(parse_path("FROM <a@b.com>", "FROM:"), None);
    }

    #[tokio::test]
    async fn data_unstuffing_and_terminator() {
        let input = b"Subject: x\r\n\r\n..leading dot\r\nbare lf\n.\r\nNEXT\r\n";
        let mut r = BufReader::new(&input[..]);
        match read_data(&mut r, 1000, 10).await.unwrap() {
            DataResult::Complete(d) => assert_eq!(d, b"Subject: x\r\n\r\n.leading dot\r\nbare lf\r\n"),
            DataResult::TooBig => panic!("unexpected"),
        }
        let mut rest = Vec::new();
        read_line(&mut r, &mut rest, 100).await.unwrap();
        assert_eq!(rest, b"NEXT\r\n");
    }

    #[tokio::test]
    async fn data_too_big_is_drained() {
        let mut input = Vec::new();
        for _ in 0..100 {
            input.extend_from_slice(b"0123456789012345678901234567890123456789\r\n");
        }
        input.extend_from_slice(b".\r\nQUIT\r\n");
        let mut r = BufReader::new(&input[..]);
        assert!(matches!(read_data(&mut r, 500, 10).await.unwrap(), DataResult::TooBig));
        let mut rest = Vec::new();
        read_line(&mut r, &mut rest, 100).await.unwrap();
        assert_eq!(rest, b"QUIT\r\n");
    }
}
