//! SMTP protocol: shared line I/O and reply handling.

pub mod client;
pub mod server;

use std::io;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug)]
pub enum LineError {
    /// Line exceeded the limit; it was consumed up to the newline and discarded.
    TooLong,
    Eof,
    Io(io::Error),
}

impl From<io::Error> for LineError {
    fn from(e: io::Error) -> Self {
        LineError::Io(e)
    }
}

/// Read one line including its terminator into `buf` (cleared first). Never holds
/// more than `max` bytes; an over-long line is drained and reported as TooLong so
/// the session can re-synchronise instead of buffering attacker-controlled data.
pub async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, buf: &mut Vec<u8>, max: usize) -> Result<(), LineError> {
    buf.clear();
    let mut overflow = false;
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            // A partial line without terminator at EOF is treated as a disconnect.
            return Err(LineError::Eof);
        }
        let (chunk, done) = match available.iter().position(|&b| b == b'\n') {
            Some(i) => (&available[..=i], true),
            None => (available, false),
        };
        let n = chunk.len();
        if !overflow {
            if buf.len() + n > max {
                overflow = true;
                buf.clear();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        r.consume(n);
        if done {
            return if overflow { Err(LineError::TooLong) } else { Ok(()) };
        }
    }
}

/// A (possibly multi-line) SMTP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn is_positive(&self) -> bool {
        (200..400).contains(&self.code)
    }
    pub fn is_permanent(&self) -> bool {
        self.code >= 500
    }

    #[cfg(test)]
    /// Enhanced status code (RFC 3463) from the first line, e.g. "5.1.1".
    pub fn enhanced(&self) -> Option<&str> {
        let first = self.lines.first()?;
        let tok = first.split_whitespace().next()?;
        let parts: Vec<&str> = tok.split('.').collect();
        (parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
            .then_some(tok)
    }

    pub fn text(&self) -> String {
        format!("{} {}", self.code, self.lines.join(" / "))
    }

    pub fn has_line_starting(&self, kw: &str) -> bool {
        self.lines.iter().any(|l| {
            l.len() >= kw.len()
                && l[..kw.len()].eq_ignore_ascii_case(kw)
                && l[kw.len()..].chars().next().is_none_or(|c| c == ' ' || c == '=')
        })
    }

    pub fn line_starting(&self, kw: &str) -> Option<&str> {
        self.lines.iter().find(|l| l.len() >= kw.len() && l[..kw.len()].eq_ignore_ascii_case(kw)).map(|s| s.as_str())
    }
}

/// Read a full reply from a server. Bounded to 100 lines × 4 KiB.
pub async fn read_reply<R: AsyncBufRead + Unpin>(r: &mut R) -> Result<Reply, io::Error> {
    let mut lines = Vec::new();
    let mut buf = Vec::with_capacity(256);
    loop {
        match read_line(r, &mut buf, 4096).await {
            Ok(()) => {}
            Err(LineError::TooLong) => return Err(io::Error::new(io::ErrorKind::InvalidData, "reply line too long")),
            Err(LineError::Eof) => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed by remote host"))
            }
            Err(LineError::Io(e)) => return Err(e),
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim_end_matches(['\r', '\n']);
        if line.len() < 3 || !line.as_bytes()[..3].iter().all(|b| b.is_ascii_digit()) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("malformed reply: {line:.100}")));
        }
        let code: u16 = line[..3].parse().unwrap();
        let sep = line.as_bytes().get(3).copied();
        lines.push(line.get(4..).unwrap_or("").to_string());
        if sep != Some(b'-') {
            return Ok(Reply { code, lines });
        }
        if lines.len() > 100 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "reply has too many lines"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn multi_line_reply() {
        let data = b"250-mx.example.com\r\n250-SIZE 1000\r\n250-STARTTLS\r\n250 8BITMIME\r\n";
        let mut r = BufReader::new(&data[..]);
        let rep = read_reply(&mut r).await.unwrap();
        assert_eq!(rep.code, 250);
        assert_eq!(rep.lines.len(), 4);
        assert!(rep.has_line_starting("STARTTLS"));
        assert!(rep.has_line_starting("SIZE"));
        assert!(!rep.has_line_starting("SIZ"));
    }

    #[tokio::test]
    async fn enhanced_code() {
        let mut r = BufReader::new(&b"550 5.1.1 <x@y.z>: user unknown\r\n"[..]);
        let rep = read_reply(&mut r).await.unwrap();
        assert_eq!(rep.enhanced(), Some("5.1.1"));
        assert!(rep.is_permanent());
    }

    #[tokio::test]
    async fn long_line_is_drained() {
        let mut data = vec![b'A'; 100];
        data.extend_from_slice(b"\r\nNOOP\r\n");
        let mut r = BufReader::with_capacity(16, &data[..]);
        let mut buf = Vec::new();
        assert!(matches!(read_line(&mut r, &mut buf, 50).await, Err(LineError::TooLong)));
        read_line(&mut r, &mut buf, 50).await.unwrap();
        assert_eq!(buf, b"NOOP\r\n");
    }
}
