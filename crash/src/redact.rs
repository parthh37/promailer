//! Scrub personal data from panic text before it can leave the machine.
//!
//! A mail server's panic messages can quote envelope addresses, client IPs
//! and file paths. Crash reports may end up in a public issue tracker, so
//! everything that looks like one of those is replaced with a placeholder.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Characters that can form an email address, an IP address (with port) or a
/// Rust path; anything else separates tokens.
fn token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@' | ':')
}

fn is_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else { return false };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn is_ip(s: &str) -> bool {
    if s.parse::<Ipv4Addr>().is_ok() || s.parse::<Ipv6Addr>().is_ok() {
        return true;
    }
    // "1.2.3.4:25"; IPv6 with a port is bracketed, so the brackets already split it off.
    s.rsplit_once(':').is_some_and(|(host, port)| {
        !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && host.parse::<Ipv4Addr>().is_ok()
    })
}

fn scrub_token(token: &str) -> String {
    // Sentence punctuation stuck to the end ("...failed for a@b.com.") is not part of the value.
    let core = token.trim_end_matches(['.', ':', '-']);
    let tail = &token[core.len()..];
    let core_ip = core.split('%').next().unwrap_or(core); // fe80::1%12 (zone index)
    if is_email(core) {
        format!("<email>{tail}")
    } else if is_ip(core_ip) {
        format!("<ip>{tail}")
    } else {
        token.to_string()
    }
}

/// Replace `C:\Users\<name>` (any drive, either slash) with `C:\Users\<user>`.
fn scrub_user_dirs(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(pos) = lower[i..].find("users").map(|p| p + i) {
        let before = text[..pos].chars().next_back();
        let after = text[pos + 5..].chars().next();
        let sep = |c: Option<char>| matches!(c, Some('\\' | '/'));
        if sep(before) && sep(after) {
            let name_start = pos + 6;
            let name_end =
                text[name_start..].find(['\\', '/', '"', '\'', ')', ' ', '\n']).map_or(text.len(), |p| p + name_start);
            out.push_str(&text[i..name_start]);
            if name_end > name_start {
                out.push_str("<user>");
            }
            i = name_end;
        } else {
            out.push_str(&text[i..pos + 5]);
            i = pos + 5;
        }
    }
    out.push_str(&text[i..]);
    out
}

/// Scrub `text`, also replacing each of `secrets` (host names, account names)
/// wherever it appears. Secrets shorter than three characters are ignored so
/// that a one-letter account name cannot shred the whole report.
pub fn redact(text: &str, secrets: &[&str]) -> String {
    let mut text = text.to_string();
    for s in secrets.iter().map(|s| s.trim()).filter(|s| s.len() >= 3) {
        text = replace_ignore_case(&text, s, "<redacted>");
    }
    let text = scrub_user_dirs(&text);
    let mut out = String::with_capacity(text.len());
    let mut token = String::new();
    for c in text.chars() {
        if token_char(c) {
            token.push(c);
        } else {
            out.push_str(&scrub_token(&token));
            token.clear();
            out.push(c);
        }
    }
    out.push_str(&scrub_token(&token));
    out
}

fn replace_ignore_case(text: &str, needle: &str, with: &str) -> String {
    let (lt, ln) = (text.to_ascii_lowercase(), needle.to_ascii_lowercase());
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while let Some(p) = lt[i..].find(&ln) {
        out.push_str(&text[i..i + p]);
        out.push_str(with);
        i += p + ln.len();
    }
    out.push_str(&text[i..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_addresses() {
        assert_eq!(redact("rcpt <jane.doe+x@mail.example.com> refused", &[]), "rcpt <<email>> refused");
        assert_eq!(redact("Err(\"bob@example.org\").", &[]), "Err(\"<email>\").");
        assert_eq!(redact("connect 203.0.113.7:25 timed out", &[]), "connect <ip> timed out");
        assert_eq!(redact("peer [2001:db8::1]:587 reset", &[]), "peer [<ip>]:587 reset");
        assert_eq!(redact("bound to ::1 and fe80::1%12", &[]), "bound to <ip> and <ip>");
        assert_eq!(redact("delivery to 10.0.0.1.", &[]), "delivery to <ip>.");
    }

    #[test]
    fn keeps_code_locations_and_rust_paths() {
        let s = "panicked at src/queue/mod.rs:432:9: std::net::IpAddr parse; version 0.1.0 took 12:34:56";
        assert_eq!(redact(s, &[]), s);
    }

    #[test]
    fn scrubs_user_profiles_and_secrets() {
        assert_eq!(
            redact(r"open C:\Users\jsmith\AppData\x.json failed", &[]),
            r"open C:\Users\<user>\AppData\x.json failed"
        );
        assert_eq!(redact("/home/x/users/al/y", &[]), "/home/x/users/<user>/y");
        assert_eq!(redact("host MAIL01 said MAIL01.corp", &["mail01", "a"]), "host <redacted> said <redacted>.corp");
    }
}
