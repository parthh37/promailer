//! Outbound SMTP client used for MX and smarthost delivery.

use super::{read_reply, Reply};
use crate::tls::Stream;
use base64::Engine;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpSocket, TcpStream};
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Connect,
    Greeting,
    Ehlo,
    StartTls,
    Auth,
    MailFrom,
    RcptTo,
    Data,
    Message,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Stage::Connect => "connect",
            Stage::Greeting => "greeting",
            Stage::Ehlo => "EHLO",
            Stage::StartTls => "STARTTLS",
            Stage::Auth => "AUTH",
            Stage::MailFrom => "MAIL FROM",
            Stage::RcptTo => "RCPT TO",
            Stage::Data => "DATA",
            Stage::Message => "end of data",
        };
        f.write_str(s)
    }
}

#[derive(Debug)]
pub enum ClientError {
    /// Network-level failure (refused, reset, timeout).
    Io(Stage, String),
    /// TLS negotiation failed (caller may retry without TLS if opportunistic).
    Tls(String),
    /// TLS required by policy but the server doesn't offer it.
    TlsUnavailable,
    /// The server answered with a negative reply.
    Reply(Stage, Reply),
    /// Message exceeds the server's advertised SIZE.
    TooLarge(u64),
    /// Addresses need SMTPUTF8 but the server doesn't support it.
    Utf8Unsupported,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Io(st, e) => write!(f, "{e} (during {st})"),
            ClientError::Tls(e) => write!(f, "TLS negotiation failed: {e}"),
            ClientError::TlsUnavailable => write!(f, "TLS required by policy but not offered by remote server"),
            ClientError::Reply(st, r) => write!(f, "{} (in reply to {st})", r.text()),
            ClientError::TooLarge(max) => {
                write!(f, "552 5.3.4 Message exceeds remote server's size limit of {max} bytes")
            }
            ClientError::Utf8Unsupported => write!(f, "553 5.6.7 Remote server does not support SMTPUTF8 addresses"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Disabled,
    Opportunistic,
    Required,
    Implicit,
}

pub struct ConnectParams<'a> {
    pub addr: SocketAddr,
    pub source: Option<IpAddr>,
    /// Hostname for SNI / certificate verification.
    pub tls_name: &'a str,
    pub helo: &'a str,
    pub tls: TlsMode,
    pub connector: &'a TlsConnector,
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub data_timeout: Duration,
    pub auth: Option<(&'a str, &'a str)>,
}

/// Per-recipient results of one transaction.
pub struct TxResult {
    pub accepted: Vec<(String, Reply)>,
    pub rejected: Vec<(String, Reply)>,
    /// Final reply after the message body (only if any recipient was accepted).
    pub data_reply: Option<Reply>,
}

pub struct SmtpClient {
    reader: BufReader<Stream>,
    pub caps: Reply,
    pub tls_info: Option<String>,
    pub messages_sent: usize,
    pub last_used: Instant,
    command_timeout: Duration,
    data_timeout: Duration,
}

async fn tcp_connect(addr: SocketAddr, source: Option<IpAddr>, timeout: Duration) -> io::Result<TcpStream> {
    let sock = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    if let Some(src) = source {
        sock.bind(SocketAddr::new(src, 0))?;
    }
    let stream = tokio::time::timeout(timeout, sock.connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection timed out"))??;
    stream.set_nodelay(true)?;
    Ok(stream)
}

impl SmtpClient {
    pub async fn connect(p: &ConnectParams<'_>) -> Result<Self, ClientError> {
        let tcp = tcp_connect(p.addr, p.source, p.connect_timeout)
            .await
            .map_err(|e| ClientError::Io(Stage::Connect, format!("connect to {} failed: {e}", p.addr)))?;
        let mut stream = Stream::Plain(tcp);
        if p.tls == TlsMode::Implicit {
            stream = tokio::time::timeout(p.command_timeout, stream.upgrade_client(p.connector, p.tls_name))
                .await
                .map_err(|_| ClientError::Tls("handshake timed out".into()))?
                .map_err(|e| ClientError::Tls(e.to_string()))?;
        }
        let tls_info = stream.tls_info();
        let mut c = SmtpClient {
            reader: BufReader::with_capacity(4096, stream),
            caps: Reply { code: 0, lines: vec![] },
            tls_info,
            messages_sent: 0,
            last_used: Instant::now(),
            command_timeout: p.command_timeout,
            data_timeout: p.data_timeout,
        };

        let greeting = c.read(Stage::Greeting).await?;
        if greeting.code != 220 {
            return Err(ClientError::Reply(Stage::Greeting, greeting));
        }
        c.ehlo(p.helo).await?;

        if matches!(p.tls, TlsMode::Opportunistic | TlsMode::Required) {
            if c.caps.has_line_starting("STARTTLS") {
                let r = c.cmd("STARTTLS", Stage::StartTls).await?;
                if r.code != 220 {
                    if p.tls == TlsMode::Required {
                        return Err(ClientError::Reply(Stage::StartTls, r));
                    }
                } else {
                    let reader = std::mem::replace(&mut c.reader, BufReader::new(Stream::Detached));
                    let tls = tokio::time::timeout(
                        p.command_timeout,
                        reader.into_inner().upgrade_client(p.connector, p.tls_name),
                    )
                    .await
                    .map_err(|_| ClientError::Tls("handshake timed out".into()))?
                    .map_err(|e| ClientError::Tls(e.to_string()))?;
                    c.tls_info = tls.tls_info();
                    c.reader = BufReader::with_capacity(4096, tls);
                    c.ehlo(p.helo).await?;
                }
            } else if p.tls == TlsMode::Required {
                let _ = c.quit().await;
                return Err(ClientError::TlsUnavailable);
            }
        }

        if let Some((user, pass)) = p.auth {
            c.authenticate(user, pass).await?;
        }
        Ok(c)
    }

    async fn read(&mut self, stage: Stage) -> Result<Reply, ClientError> {
        tokio::time::timeout(self.command_timeout, read_reply(&mut self.reader))
            .await
            .map_err(|_| ClientError::Io(stage, "timed out waiting for reply".into()))?
            .map_err(|e| ClientError::Io(stage, e.to_string()))
    }

    async fn write(&mut self, data: &[u8], stage: Stage) -> Result<(), ClientError> {
        let w = self.reader.get_mut();
        tokio::time::timeout(self.command_timeout, async {
            w.write_all(data).await?;
            w.flush().await
        })
        .await
        .map_err(|_| ClientError::Io(stage, "write timed out".into()))?
        .map_err(|e| ClientError::Io(stage, e.to_string()))
    }

    async fn cmd(&mut self, line: &str, stage: Stage) -> Result<Reply, ClientError> {
        self.write(format!("{line}\r\n").as_bytes(), stage).await?;
        self.read(stage).await
    }

    async fn ehlo(&mut self, helo: &str) -> Result<(), ClientError> {
        let r = self.cmd(&format!("EHLO {helo}"), Stage::Ehlo).await?;
        if r.code == 250 {
            self.caps = r;
            return Ok(());
        }
        if r.is_permanent() {
            // Ancient server without ESMTP.
            let r2 = self.cmd(&format!("HELO {helo}"), Stage::Ehlo).await?;
            if r2.code == 250 {
                self.caps = Reply { code: 250, lines: vec![] };
                return Ok(());
            }
            return Err(ClientError::Reply(Stage::Ehlo, r2));
        }
        Err(ClientError::Reply(Stage::Ehlo, r))
    }

    async fn authenticate(&mut self, user: &str, pass: &str) -> Result<(), ClientError> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let mechs = self
            .caps
            .line_starting("AUTH")
            .map(|l| l[4..].trim_start_matches(['=', ' ']).to_ascii_uppercase())
            .unwrap_or_default();
        let r = if mechs.split_whitespace().any(|m| m == "PLAIN") {
            let token = b64.encode(format!("\0{user}\0{pass}"));
            self.cmd(&format!("AUTH PLAIN {token}"), Stage::Auth).await?
        } else if mechs.split_whitespace().any(|m| m == "LOGIN") {
            let r = self.cmd("AUTH LOGIN", Stage::Auth).await?;
            if r.code != 334 {
                return Err(ClientError::Reply(Stage::Auth, r));
            }
            let r = self.cmd(&b64.encode(user), Stage::Auth).await?;
            if r.code != 334 {
                return Err(ClientError::Reply(Stage::Auth, r));
            }
            self.cmd(&b64.encode(pass), Stage::Auth).await?
        } else {
            return Err(ClientError::Reply(
                Stage::Auth,
                Reply {
                    code: 454,
                    lines: vec!["4.7.0 Server offers no supported AUTH mechanism (PLAIN/LOGIN)".into()],
                },
            ));
        };
        if r.code != 235 {
            return Err(ClientError::Reply(Stage::Auth, r));
        }
        Ok(())
    }

    /// Reset the session for reuse. Returns false if the connection is no longer usable.
    pub async fn reset(&mut self) -> bool {
        matches!(self.cmd("RSET", Stage::MailFrom).await, Ok(r) if r.code == 250)
    }

    pub async fn quit(&mut self) -> Result<(), ClientError> {
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let _ = self.write(b"QUIT\r\n", Stage::Message).await;
            let _ = read_reply(&mut self.reader).await;
            let _ = self.reader.get_mut().shutdown().await;
        })
        .await;
        Ok(())
    }

    fn max_size(&self) -> Option<u64> {
        self.caps.line_starting("SIZE").and_then(|l| l[4..].trim().parse::<u64>().ok()).filter(|n| *n > 0)
    }

    /// Run one mail transaction. Connection-level problems are returned as Err;
    /// per-recipient outcomes are in the TxResult.
    pub async fn send(&mut self, from: &str, rcpts: &[String], data: &[u8]) -> Result<TxResult, ClientError> {
        self.last_used = Instant::now();
        let size = data.len() as u64;
        if let Some(max) = self.max_size() {
            if size > max {
                return Err(ClientError::TooLarge(max));
            }
        }
        let needs_utf8 = !from.is_ascii() || rcpts.iter().any(|r| !r.is_ascii());
        if needs_utf8 && !self.caps.has_line_starting("SMTPUTF8") {
            return Err(ClientError::Utf8Unsupported);
        }

        let mut mail = format!("MAIL FROM:<{from}>");
        if self.caps.has_line_starting("SIZE") {
            mail.push_str(&format!(" SIZE={size}"));
        }
        if !data.is_ascii() && self.caps.has_line_starting("8BITMIME") {
            mail.push_str(" BODY=8BITMIME");
        }
        if needs_utf8 {
            mail.push_str(" SMTPUTF8");
        }

        let pipelining = self.caps.has_line_starting("PIPELINING");
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();

        if pipelining {
            let mut batch = format!("{mail}\r\n");
            for r in rcpts {
                batch.push_str(&format!("RCPT TO:<{r}>\r\n"));
            }
            self.write(batch.as_bytes(), Stage::MailFrom).await?;
            let mr = self.read(Stage::MailFrom).await?;
            // Always drain the RCPT replies to keep the stream in sync.
            let mut rcpt_replies = Vec::with_capacity(rcpts.len());
            for _ in rcpts {
                rcpt_replies.push(self.read(Stage::RcptTo).await?);
            }
            if !mr.is_positive() {
                let _ = self.reset().await;
                return Err(ClientError::Reply(Stage::MailFrom, mr));
            }
            for (r, rep) in rcpts.iter().zip(rcpt_replies) {
                if rep.is_positive() {
                    accepted.push((r.clone(), rep))
                } else {
                    rejected.push((r.clone(), rep))
                }
            }
        } else {
            let mr = self.cmd(&mail, Stage::MailFrom).await?;
            if !mr.is_positive() {
                let _ = self.reset().await;
                return Err(ClientError::Reply(Stage::MailFrom, mr));
            }
            for r in rcpts {
                let rep = self.cmd(&format!("RCPT TO:<{r}>"), Stage::RcptTo).await?;
                if rep.is_positive() {
                    accepted.push((r.clone(), rep))
                } else {
                    rejected.push((r.clone(), rep))
                }
            }
        }

        if accepted.is_empty() {
            let _ = self.reset().await;
            return Ok(TxResult { accepted, rejected, data_reply: None });
        }

        let dr = self.cmd("DATA", Stage::Data).await?;
        if dr.code != 354 {
            let _ = self.reset().await;
            return Err(ClientError::Reply(Stage::Data, dr));
        }
        self.write_body(data).await?;
        let final_reply = tokio::time::timeout(self.data_timeout, read_reply(&mut self.reader))
            .await
            .map_err(|_| ClientError::Io(Stage::Message, "timed out waiting for final reply".into()))?
            .map_err(|e| ClientError::Io(Stage::Message, e.to_string()))?;
        self.messages_sent += 1;
        self.last_used = Instant::now();
        Ok(TxResult { accepted, rejected, data_reply: Some(final_reply) })
    }

    /// Stream the message with dot-stuffing, in 64 KiB writes.
    async fn write_body(&mut self, data: &[u8]) -> Result<(), ClientError> {
        let timeout = self.data_timeout;
        let w = self.reader.get_mut();
        tokio::time::timeout(timeout, async {
            let mut buf = Vec::with_capacity(64 * 1024 + 1024);
            for line in data.split_inclusive(|&b| b == b'\n') {
                if line.first() == Some(&b'.') {
                    buf.push(b'.');
                }
                buf.extend_from_slice(line);
                if buf.len() >= 64 * 1024 {
                    w.write_all(&buf).await?;
                    buf.clear();
                }
            }
            if !data.ends_with(b"\r\n") {
                buf.extend_from_slice(b"\r\n");
            }
            buf.extend_from_slice(b".\r\n");
            w.write_all(&buf).await?;
            w.flush().await
        })
        .await
        .map_err(|_| ClientError::Io(Stage::Message, "timed out sending message body".into()))?
        .map_err(|e| ClientError::Io(Stage::Message, e.to_string()))
    }
}
