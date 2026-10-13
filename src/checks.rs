//! Deliverability diagnostics: rDNS (FCrDNS), SPF, DKIM, DMARC, MX and HELO checks.
//! Used by `promailer check` and `GET /api/v1/check/{domain}`.

use crate::config::Config;
use crate::dkim::{public_key_matches, DkimRegistry};
use crate::dns::{Dns, DnsFailure};
use base64::Engine;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Info,
}

#[derive(Debug, Serialize)]
pub struct CheckItem {
    pub check: String,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub domain: String,
    pub ips: Vec<IpAddr>,
    pub items: Vec<CheckItem>,
}

impl Report {
    fn add(&mut self, check: impl Into<String>, status: Status, detail: impl Into<String>) {
        self.items.push(CheckItem { check: check.into(), status, detail: detail.into() });
    }
    pub fn failed(&self) -> bool {
        self.items.iter().any(|i| i.status == Status::Fail)
    }
}

/// Best-effort local address used for outbound traffic (no packets are sent).
pub fn default_outbound_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:53").ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

fn is_private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn looks_generic(ptr: &str, ip: IpAddr) -> bool {
    let p = ptr.to_lowercase();
    let ip_s = ip.to_string();
    let dashed = ip_s.replace('.', "-");
    ["dynamic", "dyn.", "dhcp", "pool", "dsl", "cable", "ppp", "customer", "broadband", "static.", "unassigned"]
        .iter()
        .any(|k| p.contains(k))
        || p.contains(&dashed)
        || p.contains(&ip_s)
}

fn tag<'a>(record: &'a str, name: &str) -> Option<&'a str> {
    record.split(';').map(str::trim).find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Compare the published DKIM TXT record at `name` with our public key bytes.
pub async fn dkim_record_status(dns: &Dns, name: &str, ours: &[u8]) -> (Status, String) {
    match dns.txt(name).await {
        Ok(txts) => {
            let rec = txts.join("");
            let p = tag(&rec, "p").unwrap_or("");
            if p.is_empty() {
                return (Status::Fail, format!("{name} has no p= key (revoked?)"));
            }
            match base64::engine::general_purpose::STANDARD.decode(p.replace([' ', '\t'], "")) {
                Ok(dns_key) if public_key_matches(&dns_key, ours) => {
                    (Status::Pass, format!("{name} matches the configured private key"))
                }
                Ok(_) => (
                    Status::Fail,
                    format!("{name} does not match the configured private key; signatures will fail. Publish the record shown for this key"),
                ),
                Err(_) => (Status::Fail, format!("{name} p= is not valid base64")),
            }
        }
        Err(DnsFailure::NotFound) => (Status::Fail, format!("No TXT record at {name}")),
        Err(e) => (Status::Warn, format!("lookup of {name} failed: {e}")),
    }
}

pub async fn run(dns: &Dns, cfg: &Config, dkim: &DkimRegistry, domain: &str, ips_override: &[IpAddr]) -> Report {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let mut ips: Vec<IpAddr> = if !ips_override.is_empty() {
        ips_override.to_vec()
    } else if !cfg.outbound_ips.is_empty() {
        cfg.outbound_ips.iter().map(|o| o.address).collect()
    } else {
        default_outbound_ip().into_iter().collect()
    };
    ips.dedup();
    let mut r = Report { domain: domain.clone(), ips: ips.clone(), items: vec![] };

    // --- rDNS / FCrDNS per sending IP -------------------------------------
    for ip in &ips {
        let helo = cfg
            .outbound_ips
            .iter()
            .find(|o| o.address == *ip)
            .and_then(|o| o.helo.clone())
            .unwrap_or_else(|| cfg.server.hostname.clone());
        let name = format!("rDNS {ip}");
        if is_private(*ip) {
            r.add(
                &name,
                Status::Warn,
                format!(
                    "{ip} is a private/NAT address. Pass your public IP with --ip so the real PTR record is checked."
                ),
            );
            continue;
        }
        match dns.ptr(*ip).await {
            Ok(ptrs) => {
                let ptr = ptrs[0].clone();
                match dns.fcrdns(*ip).await {
                    Ok(Some(confirmed)) => {
                        r.add(&name, Status::Pass, format!("PTR {confirmed} resolves back to {ip} (forward-confirmed)"));
                        if !confirmed.eq_ignore_ascii_case(&helo) {
                            r.add(format!("HELO {ip}"), Status::Warn, format!(
                                "EHLO name '{helo}' differs from PTR '{confirmed}'. Set server.hostname (or outbound_ip.helo) to the PTR name."
                            ));
                        } else {
                            r.add(format!("HELO {ip}"), Status::Pass, format!("EHLO name matches PTR ({helo})"));
                        }
                        if looks_generic(&confirmed, *ip) {
                            r.add(&name, Status::Warn, format!(
                                "PTR '{confirmed}' looks like a generic/residential name; many receivers penalise this. Use a name like mail.{domain}"
                            ));
                        }
                    }
                    Ok(None) => r.add(&name, Status::Fail, format!(
                        "PTR {ptr} does not resolve back to {ip}. Add an A record: {ptr} -> {ip}"
                    )),
                    Err(e) => r.add(&name, Status::Warn, format!("PTR {ptr} found but forward lookup failed: {e}")),
                }
            }
            Err(DnsFailure::NotFound) => r.add(&name, Status::Fail, format!(
                "No PTR record for {ip}. Ask your hosting provider/ISP to set reverse DNS to '{helo}'. Gmail, Outlook and Yahoo reject mail without rDNS."
            )),
            Err(e) => r.add(&name, Status::Warn, format!("PTR lookup failed: {e}")),
        }
    }

    // --- HELO hostname A record -------------------------------------------
    let host = &cfg.server.hostname;
    match dns.ips(host, true).await {
        Ok(addrs) => {
            let matches = ips.iter().any(|ip| addrs.contains(ip));
            if matches || ips.iter().all(|ip| is_private(*ip)) {
                r.add("Hostname", Status::Pass, format!("{host} resolves to {addrs:?}"));
            } else {
                r.add(
                    "Hostname",
                    Status::Warn,
                    format!("{host} resolves to {addrs:?}, which doesn't include the sending IP(s)"),
                );
            }
        }
        Err(_) => r.add("Hostname", Status::Fail, format!("server.hostname '{host}' has no A/AAAA record")),
    }

    // --- SPF -----------------------------------------------------------------
    match dns.txt(&domain).await {
        Ok(txts) => {
            let spf: Vec<&String> = txts.iter().filter(|t| t.to_lowercase().starts_with("v=spf1")).collect();
            match spf.len() {
                0 => r.add(
                    "SPF",
                    Status::Fail,
                    format!(
                        "No SPF record. Publish TXT on {domain}: \"v=spf1 {} ~all\"",
                        ips.iter()
                            .map(|ip| if ip.is_ipv4() { format!("ip4:{ip}") } else { format!("ip6:{ip}") })
                            .collect::<Vec<_>>()
                            .join(" ")
                    ),
                ),
                1 => {
                    r.add("SPF record", Status::Info, spf[0].clone());
                    if spf[0].contains("+all") {
                        r.add(
                            "SPF",
                            Status::Fail,
                            "SPF uses '+all', which authorises the whole internet to send as you",
                        );
                    }
                    for ip in ips.iter().filter(|ip| !is_private(**ip)) {
                        let out = dns.spf_check(*ip, host, host, &format!("postmaster@{domain}")).await;
                        let (status, word) = match out.result() {
                            mail_auth::SpfResult::Pass => (Status::Pass, "pass"),
                            mail_auth::SpfResult::SoftFail => (Status::Fail, "softfail"),
                            mail_auth::SpfResult::Fail => (Status::Fail, "fail"),
                            mail_auth::SpfResult::Neutral => (Status::Warn, "neutral"),
                            mail_auth::SpfResult::None => (Status::Fail, "none"),
                            mail_auth::SpfResult::TempError => (Status::Warn, "temperror"),
                            mail_auth::SpfResult::PermError => {
                                (Status::Fail, "permerror (syntax error or >10 DNS lookups)")
                            }
                        };
                        let hint = if status == Status::Pass {
                            String::new()
                        } else {
                            format!(". Add '{}:{ip}' to the SPF record", if ip.is_ipv4() { "ip4" } else { "ip6" })
                        };
                        r.add(format!("SPF {ip}"), status, format!("SPF evaluation for {ip}: {word}{hint}"));
                    }
                }
                _ => r.add(
                    "SPF",
                    Status::Fail,
                    format!("{} SPF records found; exactly one is allowed (permerror)", spf.len()),
                ),
            }
        }
        Err(DnsFailure::NotFound) => r.add("SPF", Status::Fail, format!("No TXT records on {domain}; SPF missing")),
        Err(e) => r.add("SPF", Status::Warn, format!("TXT lookup failed: {e}")),
    }

    // --- DKIM ----------------------------------------------------------------
    let keys = dkim.public_keys(&domain);
    if keys.is_empty() {
        r.add("DKIM", Status::Fail, format!(
            "No DKIM key configured for {domain}. Create one under DKIM Keys in Promailer Manager, or run `promailer dkim generate --domain {domain} --selector s1` and add a [[dkim]] section"
        ));
    }
    for (selector, ours) in keys {
        let name = crate::dkim::dns_name(&domain, &selector);
        let (status, detail) = dkim_record_status(dns, &name, &ours).await;
        r.add(format!("DKIM {selector}"), status, detail);
    }

    // --- DMARC ---------------------------------------------------------------
    match dns.txt(&format!("_dmarc.{domain}")).await {
        Ok(txts) => match txts.iter().find(|t| t.to_lowercase().starts_with("v=dmarc1")) {
            Some(rec) => {
                let p = tag(rec, "p").unwrap_or("").to_lowercase();
                let status = match p.as_str() {
                    "reject" | "quarantine" => Status::Pass,
                    "none" => Status::Warn,
                    _ => Status::Fail,
                };
                let mut detail = rec.to_string();
                if p == "none" {
                    detail.push_str(" (monitoring only; move to p=quarantine once SPF/DKIM pass)");
                }
                if tag(rec, "rua").is_none() {
                    detail.push_str(" (no rua= reporting address)");
                }
                r.add("DMARC", status, detail);
            }
            None => r.add("DMARC", Status::Fail, format!("No DMARC record. Publish TXT on _dmarc.{domain}: \"v=DMARC1; p=none; rua=mailto:dmarc@{domain}\"")),
        },
        Err(DnsFailure::NotFound) => r.add("DMARC", Status::Fail, format!(
            "No DMARC record. Publish TXT on _dmarc.{domain}: \"v=DMARC1; p=none; rua=mailto:dmarc@{domain}\" (required by Gmail/Yahoo for bulk senders)"
        )),
        Err(e) => r.add("DMARC", Status::Warn, format!("lookup failed: {e}")),
    }

    // --- MX (needed to receive bounces / replies) ---------------------------
    match dns.mx(&domain).await {
        Ok(mx) => r.add("MX", Status::Info, mx.iter().map(|(p, h)| format!("{p} {h}")).collect::<Vec<_>>().join(", ")),
        Err(DnsFailure::NotFound) => r.add(
            "MX",
            Status::Warn,
            format!("{domain} has no MX record; replies and bounces to this domain can't be received"),
        ),
        Err(e) => r.add("MX", Status::Warn, format!("lookup failed: {e}")),
    }

    r
}

pub fn print(report: &Report) {
    println!("Deliverability report for {}  (sending IPs: {:?})\n", report.domain, report.ips);
    for i in &report.items {
        let mark = match i.status {
            Status::Pass => "[ OK ]",
            Status::Warn => "[WARN]",
            Status::Fail => "[FAIL]",
            Status::Info => "[INFO]",
        };
        println!("{mark} {:<22} {}", i.check, i.detail);
    }
    let fails = report.items.iter().filter(|i| i.status == Status::Fail).count();
    let warns = report.items.iter().filter(|i| i.status == Status::Warn).count();
    println!("\n{fails} failure(s), {warns} warning(s)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_ptr_detection() {
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(looks_generic("203-0-113-7.dynamic.isp.net", ip));
        assert!(!looks_generic("mail.example.com", ip));
    }

    #[test]
    fn tag_parsing() {
        assert_eq!(tag("v=DMARC1; p=reject; rua=mailto:x@y", "p"), Some("reject"));
        assert_eq!(tag("v=DKIM1; k=rsa; p=ABC", "P"), Some("ABC"));
        assert_eq!(tag("v=DKIM1", "p"), None);
    }
}
