//! RFC 5322 helpers: header inspection, required-header completion, Received
//! trace headers and address extraction. Deliberately allocation-light: we
//! only ever look at the header block, never parse MIME bodies.

use chrono::Utc;

/// Byte offset where the body starts (after the blank line), or len if no body.
pub fn header_end(msg: &[u8]) -> usize {
    if let Some(p) = find(msg, b"\r\n\r\n") {
        return p + 4;
    }
    if let Some(p) = find(msg, b"\n\n") {
        return p + 2;
    }
    msg.len()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Iterate unfolded headers as (name, value) pairs.
pub fn headers(msg: &[u8]) -> Vec<(String, String)> {
    let block = &msg[..header_end(msg)];
    let text = String::from_utf8_lossy(block);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            out.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    out
}

pub fn header_value(hdrs: &[(String, String)], name: &str) -> Option<String> {
    hdrs.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.clone())
}

pub fn count_received(hdrs: &[(String, String)]) -> usize {
    hdrs.iter().filter(|(n, _)| n.eq_ignore_ascii_case("Received")).count()
}

/// Normalise bare LF / bare CR line endings to CRLF (RFC 5321 requires CRLF on the wire,
/// and DKIM canonicalisation assumes it). Returns the input untouched when already clean.
pub fn normalize_crlf(data: Vec<u8>) -> Vec<u8> {
    let needs = data.iter().enumerate().any(|(i, &b)| {
        (b == b'\n' && (i == 0 || data[i - 1] != b'\r')) || (b == b'\r' && data.get(i + 1) != Some(&b'\n'))
    });
    if !needs {
        return data;
    }
    let mut out = Vec::with_capacity(data.len() + data.len() / 32);
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' => {
                out.extend_from_slice(b"\r\n");
                if data.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => out.extend_from_slice(b"\r\n"),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

pub fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@').map(|(_, d)| d.trim_end_matches('>').to_lowercase()).unwrap_or_default()
}

pub fn new_message_id(hostname: &str) -> String {
    format!("<{}@{}>", ulid::Ulid::new().to_string().to_lowercase(), hostname)
}

pub fn rfc2822_now() -> String {
    Utc::now().to_rfc2822()
}

/// Prepend headers that IIS also adds when missing: Message-ID and Date.
/// Returns the (possibly) modified message.
pub fn complete_headers(msg: Vec<u8>, hostname: &str, from_fallback: Option<&str>) -> Vec<u8> {
    let hdrs = headers(&msg);
    let mut prefix = String::new();
    if header_value(&hdrs, "Message-ID").is_none() {
        prefix.push_str(&format!("Message-ID: {}\r\n", new_message_id(hostname)));
    }
    if header_value(&hdrs, "Date").is_none() {
        prefix.push_str(&format!("Date: {}\r\n", rfc2822_now()));
    }
    if header_value(&hdrs, "From").is_none() {
        if let Some(f) = from_fallback.filter(|f| !f.is_empty()) {
            prefix.push_str(&format!("From: <{f}>\r\n"));
        }
    }
    if prefix.is_empty() {
        return msg;
    }
    // Keep trace headers (Received / Return-Path) on top, as RFC 5321 §4.4 expects.
    let at = trace_block_end(&msg);
    let mut out = Vec::with_capacity(prefix.len() + msg.len());
    out.extend_from_slice(&msg[..at]);
    out.extend_from_slice(prefix.as_bytes());
    out.extend_from_slice(&msg[at..]);
    out
}

/// Byte offset just past the leading Received:/Return-Path: fields (with continuations).
fn trace_block_end(msg: &[u8]) -> usize {
    let mut pos = 0;
    let mut in_trace = false;
    for line in msg[..header_end(msg)].split_inclusive(|&b| b == b'\n') {
        let is_cont = matches!(line.first(), Some(b' ') | Some(b'\t'));
        if is_cont && in_trace {
            pos += line.len();
            continue;
        }
        let lower = line.iter().take(12).map(|b| b.to_ascii_lowercase()).collect::<Vec<u8>>();
        if lower.starts_with(b"received:") || lower.starts_with(b"return-path:") {
            in_trace = true;
            pos += line.len();
        } else {
            break;
        }
    }
    pos
}

pub struct ReceivedInfo<'a> {
    pub helo: &'a str,
    pub client_ip: std::net::IpAddr,
    pub client_ptr: Option<&'a str>,
    pub hostname: &'a str,
    pub protocol: &'a str,
    pub tls: Option<&'a str>,
    pub id: &'a str,
    pub recipient: Option<&'a str>,
    pub auth_user: Option<&'a str>,
}

pub fn received_header(r: &ReceivedInfo) -> String {
    let ptr = r.client_ptr.unwrap_or("unknown");
    let mut h = format!(
        "Received: from {} ({} [{}])\r\n\tby {} (Promailer) with {}",
        sanitize(r.helo),
        sanitize(ptr),
        r.client_ip,
        r.hostname,
        r.protocol
    );
    if let Some(tls) = r.tls {
        h.push_str(&format!(" (using {})", sanitize(tls)));
    }
    if let Some(u) = r.auth_user {
        h.push_str(&format!(" (authenticated as {})", sanitize(u)));
    }
    h.push_str(&format!("\r\n\tid {}", r.id));
    if let Some(rcpt) = r.recipient {
        h.push_str(&format!("\r\n\tfor <{}>", sanitize(rcpt)));
    }
    h.push_str(&format!(";\r\n\t{}\r\n", rfc2822_now()));
    h
}

/// Strip characters that could break header structure.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control() && *c != '(' && *c != ')').take(255).collect()
}

/// Extract bare addresses from an address-list header value:
/// `"Doe, John" <j@x.com>, b@y.com (Bob), Group: c@z.com;`
pub fn parse_address_list(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let (mut in_quote, mut depth_angle, mut depth_paren) = (false, 0i32, 0i32);
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if in_quote => {
                cur.push(c);
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            '"' if depth_paren == 0 => {
                in_quote = !in_quote;
                cur.push(c);
            }
            '(' if !in_quote => depth_paren += 1,
            ')' if !in_quote && depth_paren > 0 => depth_paren -= 1,
            _ if depth_paren > 0 => {}
            '<' if !in_quote => {
                depth_angle += 1;
                cur.push(c);
            }
            '>' if !in_quote => {
                depth_angle -= 1;
                cur.push(c);
            }
            ':' if !in_quote && depth_angle == 0 => cur.clear(), // group name
            ',' | ';' if !in_quote && depth_angle == 0 => {
                if let Some(a) = extract_addr(&cur) {
                    out.push(a);
                }
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if let Some(a) = extract_addr(&cur) {
        out.push(a);
    }
    out
}

fn extract_addr(token: &str) -> Option<String> {
    let t = token.trim();
    let addr = match (t.rfind('<'), t.rfind('>')) {
        (Some(s), Some(e)) if e > s => &t[s + 1..e],
        _ => t,
    };
    let addr = addr.trim();
    (addr.contains('@') && !addr.contains(char::is_whitespace)).then(|| addr.to_string())
}

/// Remove all instances of a header (with continuation lines) from the header block.
pub fn remove_header(msg: &[u8], name: &str) -> Vec<u8> {
    let end = header_end(msg);
    let (head, body) = msg.split_at(end);
    let mut out = Vec::with_capacity(msg.len());
    let mut skipping = false;
    for line in head.split_inclusive(|&b| b == b'\n') {
        let is_cont = matches!(line.first(), Some(b' ') | Some(b'\t'));
        if !is_cont {
            skipping = line.len() > name.len()
                && line[..name.len()].eq_ignore_ascii_case(name.as_bytes())
                && line[name.len()] == b':';
        }
        if !skipping {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(body);
    out
}

/// Basic syntactic check of an envelope address (local@domain, no spaces/controls).
pub fn valid_mailbox(addr: &str) -> bool {
    if addr.len() > 320 || addr.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    match addr.rsplit_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && local.len() <= 64
                && !domain.is_empty()
                && domain.len() <= 255
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !domain.contains("..")
                && (domain.contains('.') || (domain.starts_with('[') && domain.ends_with(']')))
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfolds_headers() {
        let m = b"Subject: hello\r\n world\r\nFrom: a@b.c\r\n\r\nbody";
        let h = headers(m);
        assert_eq!(h[0], ("Subject".into(), "hello world".into()));
        assert_eq!(header_value(&h, "from").unwrap(), "a@b.c");
    }

    #[test]
    fn address_lists() {
        let v = parse_address_list(r#""Doe, John" <j@x.com>, b@y.com (Bob), Team: c@z.com, d@z.com;"#);
        assert_eq!(v, vec!["j@x.com", "b@y.com", "c@z.com", "d@z.com"]);
    }

    #[test]
    fn crlf_normalisation() {
        assert_eq!(normalize_crlf(b"a\nb\r\nc\r".to_vec()), b"a\r\nb\r\nc\r\n");
        assert_eq!(normalize_crlf(b"a\r\nb".to_vec()), b"a\r\nb");
    }

    #[test]
    fn removes_bcc() {
        let m = b"To: a@b.c\r\nBcc: x@y.z,\r\n w@y.z\r\nSubject: s\r\n\r\nBcc: body stays\r\n";
        let out = remove_header(m, "Bcc");
        assert_eq!(out, b"To: a@b.c\r\nSubject: s\r\n\r\nBcc: body stays\r\n");
    }

    #[test]
    fn completes_missing_headers() {
        let out = complete_headers(b"Subject: x\r\n\r\nhi".to_vec(), "mx.example.com", Some("a@b.c"));
        let h = headers(&out);
        assert!(header_value(&h, "Message-ID").unwrap().ends_with("@mx.example.com>"));
        assert!(header_value(&h, "Date").is_some());
        assert_eq!(header_value(&h, "From").unwrap(), "<a@b.c>");
    }

    #[test]
    fn missing_headers_go_below_trace_block() {
        let m = b"Received: from x\r\n\tby y; date\r\nFrom: a@b.c\r\n\r\nhi".to_vec();
        let out = String::from_utf8(complete_headers(m, "h.example", None)).unwrap();
        assert!(out.starts_with("Received: from x\r\n\tby y; date\r\nMessage-ID: "));
    }

    #[test]
    fn mailbox_validation() {
        assert!(valid_mailbox("user@example.com"));
        assert!(!valid_mailbox("user@localhost"));
        assert!(!valid_mailbox("us er@example.com"));
        assert!(!valid_mailbox("@example.com"));
    }
}
