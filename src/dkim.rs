//! DKIM signing (RFC 6376 / RFC 8463) and key management.
//!
//! Signers are selected by the RFC5322.From domain, which is what DMARC aligns
//! against. A message is signed once when it is queued; retries reuse the
//! signed bytes.

use crate::config::{DkimAlgorithm, DkimConfig};
use crate::message;
use anyhow::{bail, Context, Result};
use base64::Engine;
use mail_auth::common::crypto::{Ed25519Key, RsaKey, Sha256};
use mail_auth::common::headers::HeaderWriter;
use mail_auth::dkim::{Canonicalization, DkimSigner, Done};
use rustls::pki_types::PrivateKeyDer;
use std::collections::HashMap;
use std::path::Path;

enum Signer {
    Rsa(DkimSigner<RsaKey<Sha256>, Done>),
    Ed25519(DkimSigner<Ed25519Key, Done>),
}

struct Entry {
    domain: String,
    selector: String,
    include_subdomains: bool,
    signer: Signer,
    /// Public key bytes as they would appear (base64-decoded) in DNS `p=`.
    public_key: Vec<u8>,
}

pub struct DkimRegistry {
    by_domain: HashMap<String, Vec<Entry>>,
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let pem = std::fs::read(path).with_context(|| format!("reading DKIM key {}", path.display()))?;
    rustls_pemfile::private_key(&mut pem.as_slice())
        .with_context(|| format!("parsing DKIM key {}", path.display()))?
        .with_context(|| format!("no private key in {}", path.display()))
}

impl DkimRegistry {
    pub fn empty() -> Self {
        Self { by_domain: HashMap::new() }
    }

    pub fn load(configs: &[DkimConfig]) -> Result<Self> {
        let mut by_domain: HashMap<String, Vec<Entry>> = HashMap::new();
        for c in configs {
            let headers: Vec<String> = c.headers.clone();
            let key = load_private_key(&c.private_key)?;
            let expire = c.expire.map(|d| d.as_secs()).unwrap_or(0);
            let (signer, public_key) = match c.algorithm {
                DkimAlgorithm::RsaSha256 => {
                    let k = RsaKey::<Sha256>::from_key_der(key)
                        .map_err(|e| anyhow::anyhow!("DKIM RSA key {}: {e}", c.private_key.display()))?;
                    let public = k.public_key();
                    let mut s = DkimSigner::from_key(k)
                        .domain(c.domain.clone())
                        .selector(c.selector.clone())
                        .headers(headers)
                        .header_canonicalization(Canonicalization::Relaxed)
                        .body_canonicalization(Canonicalization::Relaxed);
                    if expire > 0 {
                        s = s.expiration(expire);
                    }
                    (Signer::Rsa(s), public)
                }
                DkimAlgorithm::Ed25519Sha256 => {
                    let der = match &key {
                        PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
                        _ => bail!("Ed25519 DKIM key {} must be PKCS#8", c.private_key.display()),
                    };
                    let k = Ed25519Key::from_pkcs8_maybe_unchecked_der(&der)
                        .map_err(|e| anyhow::anyhow!("DKIM Ed25519 key {}: {e}", c.private_key.display()))?;
                    let public = k.public_key();
                    let mut s = DkimSigner::from_key(k)
                        .domain(c.domain.clone())
                        .selector(c.selector.clone())
                        .headers(headers)
                        .header_canonicalization(Canonicalization::Relaxed)
                        .body_canonicalization(Canonicalization::Relaxed);
                    if expire > 0 {
                        s = s.expiration(expire);
                    }
                    (Signer::Ed25519(s), public)
                }
            };
            by_domain.entry(c.domain.clone()).or_default().push(Entry {
                domain: c.domain.clone(),
                selector: c.selector.clone(),
                include_subdomains: c.include_subdomains,
                signer,
                public_key,
            });
        }
        Ok(Self { by_domain })
    }

    fn entries_for(&self, domain: &str) -> Option<&Vec<Entry>> {
        if let Some(e) = self.by_domain.get(domain) {
            return Some(e);
        }
        // Walk up the labels for include_subdomains entries.
        let mut rest = domain;
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(e) = self.by_domain.get(parent) {
                if e.iter().any(|x| x.include_subdomains) {
                    return Some(e);
                }
            }
            rest = parent;
        }
        None
    }

    /// Public keys configured for a domain: (selector, p= bytes).
    pub fn public_keys(&self, domain: &str) -> Vec<(String, Vec<u8>)> {
        self.by_domain
            .get(domain)
            .map(|v| v.iter().map(|e| (e.selector.clone(), e.public_key.clone())).collect())
            .unwrap_or_default()
    }

    /// Sign `msg` if a key exists for its From: domain. Returns the message with
    /// DKIM-Signature header(s) prepended, and the signing domains used.
    pub fn sign(&self, msg: Vec<u8>) -> (Vec<u8>, Vec<String>) {
        if self.by_domain.is_empty() {
            return (msg, vec![]);
        }
        let hdrs = message::headers(&msg);
        let Some(from) = message::header_value(&hdrs, "From") else {
            return (msg, vec![]);
        };
        let Some(addr) = message::parse_address_list(&from).into_iter().next() else {
            return (msg, vec![]);
        };
        let domain = message::domain_of(&addr);
        let Some(entries) = self.entries_for(&domain) else {
            return (msg, vec![]);
        };

        let mut prefix = String::new();
        let mut used = Vec::new();
        for e in entries {
            let res = match &e.signer {
                Signer::Rsa(s) => s.sign(&msg).map(|sig| sig.to_header()),
                Signer::Ed25519(s) => s.sign(&msg).map(|sig| sig.to_header()),
            };
            match res {
                Ok(h) => {
                    prefix.push_str(&h);
                    used.push(format!("{}/{}", e.domain, e.selector));
                }
                Err(err) => {
                    tracing::error!(domain = %e.domain, selector = %e.selector, error = %err, "DKIM signing failed")
                }
            }
        }
        if prefix.is_empty() {
            return (msg, used);
        }
        let mut out = Vec::with_capacity(prefix.len() + msg.len());
        out.extend_from_slice(prefix.as_bytes());
        out.extend_from_slice(&msg);
        (out, used)
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

pub struct GeneratedKey {
    pub private_pem: String,
    pub dns_name: String,
    pub dns_value: String,
}

fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn generate(domain: &str, selector: &str, alg: DkimAlgorithm, bits: usize) -> Result<GeneratedKey> {
    let (private_pem, p, k) = match alg {
        DkimAlgorithm::RsaSha256 => {
            use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
            if !(2048..=4096).contains(&bits) {
                bail!("RSA key size must be between 2048 and 4096 bits (the signing library rejects smaller keys)");
            }
            let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, bits).context("generating RSA key")?;
            let pem = key.to_pkcs8_pem(LineEnding::LF).context("encoding key")?.to_string();
            let spki = rsa::RsaPublicKey::from(&key).to_public_key_der().context("encoding public key")?;
            (pem, spki.as_bytes().to_vec(), "rsa")
        }
        DkimAlgorithm::Ed25519Sha256 => {
            let der = Ed25519Key::generate_pkcs8().map_err(|e| anyhow::anyhow!("{e}"))?;
            let key = Ed25519Key::from_pkcs8_der(&der).map_err(|e| anyhow::anyhow!("{e}"))?;
            (pem_encode("PRIVATE KEY", &der), key.public_key(), "ed25519")
        }
    };
    Ok(GeneratedKey { private_pem, dns_name: dns_name(domain, selector), dns_value: dns_value(k, &p) })
}

pub fn dns_name(domain: &str, selector: &str) -> String {
    format!("{selector}._domainkey.{domain}")
}

fn dns_value(k: &str, public: &[u8]) -> String {
    format!("v=DKIM1; k={k}; p={}", base64::engine::general_purpose::STANDARD.encode(public))
}

/// Public key bytes (`p=`) for a configured key, read from its private key file:
/// SubjectPublicKeyInfo DER for RSA (as `generate` publishes), raw 32 bytes for Ed25519.
pub fn public_key_bytes(c: &DkimConfig) -> Result<Vec<u8>> {
    match c.algorithm {
        DkimAlgorithm::RsaSha256 => {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
            let pem = std::fs::read_to_string(&c.private_key)
                .with_context(|| format!("reading DKIM key {}", c.private_key.display()))?;
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(&pem)
                .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(&pem))
                .with_context(|| format!("parsing RSA key {}", c.private_key.display()))?;
            Ok(rsa::RsaPublicKey::from(&key).to_public_key_der().context("encoding public key")?.as_bytes().to_vec())
        }
        DkimAlgorithm::Ed25519Sha256 => {
            let der = match load_private_key(&c.private_key)? {
                PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der().to_vec(),
                _ => bail!("Ed25519 DKIM key {} must be PKCS#8", c.private_key.display()),
            };
            let k = Ed25519Key::from_pkcs8_maybe_unchecked_der(&der)
                .map_err(|e| anyhow::anyhow!("DKIM Ed25519 key {}: {e}", c.private_key.display()))?;
            Ok(k.public_key())
        }
    }
}

/// The TXT record (name, value) to publish for a configured key.
pub fn dns_record(c: &DkimConfig) -> Result<(String, String)> {
    let k = match c.algorithm {
        DkimAlgorithm::RsaSha256 => "rsa",
        DkimAlgorithm::Ed25519Sha256 => "ed25519",
    };
    Ok((dns_name(&c.domain, &c.selector), dns_value(k, &public_key_bytes(c)?)))
}

/// DNS `p=` may hold SubjectPublicKeyInfo (standard) or a bare PKCS#1 RSAPublicKey.
/// ring exposes PKCS#1, which is the tail of the SPKI encoding.
pub fn public_key_matches(dns_p: &[u8], ours: &[u8]) -> bool {
    !ours.is_empty() && (dns_p == ours || dns_p.ends_with(ours) || ours.ends_with(dns_p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::default_dkim_headers;

    fn registry_for(alg: DkimAlgorithm, bits: usize) -> (DkimRegistry, GeneratedKey, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let g = generate("example.com", "s1", alg, bits).unwrap();
        let path = dir.path().join("k.pem");
        std::fs::write(&path, &g.private_pem).unwrap();
        let reg = DkimRegistry::load(&[DkimConfig {
            domain: "example.com".into(),
            selector: "s1".into(),
            private_key: path,
            algorithm: alg,
            headers: default_dkim_headers(),
            include_subdomains: true,
            expire: None,
        }])
        .unwrap();
        (reg, g, dir)
    }

    #[test]
    fn dns_record_rederived_from_key_file_matches_generated() {
        for alg in [DkimAlgorithm::RsaSha256, DkimAlgorithm::Ed25519Sha256] {
            let dir = tempfile::tempdir().unwrap();
            let g = generate("example.com", "s1", alg, 2048).unwrap();
            let path = dir.path().join("k.pem");
            std::fs::write(&path, &g.private_pem).unwrap();
            let c = DkimConfig {
                domain: "example.com".into(),
                selector: "s1".into(),
                private_key: path,
                algorithm: alg,
                headers: default_dkim_headers(),
                include_subdomains: false,
                expire: None,
            };
            assert_eq!(dns_record(&c).unwrap(), (g.dns_name.clone(), g.dns_value.clone()));
        }
    }

    #[test]
    fn signs_matching_from_domain_rsa() {
        let (reg, g, _d) = registry_for(DkimAlgorithm::RsaSha256, 2048);
        let msg = b"From: Test <a@example.com>\r\nTo: b@x.org\r\nSubject: hi\r\n\r\nbody\r\n".to_vec();
        let (signed, used) = reg.sign(msg);
        assert_eq!(used, vec!["example.com/s1"]);
        assert!(signed.starts_with(b"DKIM-Signature: "));
        // The DNS record we print must correspond to the key we sign with.
        let p64 = g.dns_value.split("p=").nth(1).unwrap();
        let p = base64::engine::general_purpose::STANDARD.decode(p64).unwrap();
        assert!(public_key_matches(&p, &reg.public_keys("example.com")[0].1));
    }

    /// Verify signatures exactly as a receiver would, with the DNS record we tell
    /// users to publish served from a pre-filled resolver cache (no network).
    async fn verify_offline(signed: &[u8], g: &GeneratedKey) -> mail_auth::DkimResult {
        use mail_auth::common::parse::TxtRecordParser;
        use mail_auth::common::verify::DomainKey;
        use mail_auth::{AuthenticatedMessage, MessageAuthenticator, ResolverCache, Txt};
        let cache = crate::dns::TtlCache::<Box<str>, Txt>::new();
        let key = DomainKey::parse(g.dns_value.as_bytes()).unwrap();
        let expires = std::time::Instant::now() + std::time::Duration::from_secs(600);
        cache.insert(format!("{}.", g.dns_name).into_boxed_str(), key.into(), expires);
        let auth = MessageAuthenticator::new_cloudflare().unwrap();
        let msg = AuthenticatedMessage::parse(signed).unwrap();
        let out = auth.verify_dkim(mail_auth::Parameters::new(&msg).with_txt_cache(&cache)).await;
        out.first().map(|o| o.result().clone()).unwrap_or(mail_auth::DkimResult::None)
    }

    #[tokio::test]
    async fn signatures_verify_against_published_record() {
        for (alg, bits) in [(DkimAlgorithm::RsaSha256, 2048), (DkimAlgorithm::Ed25519Sha256, 0)] {
            let (reg, g, _d) = registry_for(alg, bits);
            let msg = b"From: a@example.com\r\nTo: b@x.org\r\nSubject: verify me\r\nDate: Mon, 12 Oct 2026 10:00:00 +0000\r\n\r\nline one\r\n.dot line\r\n".to_vec();
            let (signed, _) = reg.sign(msg);
            assert_eq!(verify_offline(&signed, &g).await, mail_auth::DkimResult::Pass, "{alg:?}");
            // Tampering must break the signature.
            let tampered = String::from_utf8(signed).unwrap().replace("verify me", "tampered");
            assert!(matches!(verify_offline(tampered.as_bytes(), &g).await, mail_auth::DkimResult::Fail(_)), "{alg:?}");
        }
    }

    #[test]
    fn signs_subdomain_and_skips_foreign() {
        let (reg, _g, _d) = registry_for(DkimAlgorithm::Ed25519Sha256, 0);
        let (_, used) = reg.sign(b"From: a@news.example.com\r\n\r\nx\r\n".to_vec());
        assert_eq!(used.len(), 1);
        let (out, used) = reg.sign(b"From: a@other.com\r\n\r\nx\r\n".to_vec());
        assert!(used.is_empty());
        assert!(out.starts_with(b"From:"));
    }
}
