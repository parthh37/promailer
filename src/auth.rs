//! Credential handling: SMTP AUTH users (Argon2) and API keys (SHA-256).

use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing failed: {e}"))
}

pub fn verify_password(password: &str, phc: &str) -> bool {
    match PasswordHash::new(phc) {
        Ok(parsed) => Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

/// Generate a random API key: `pm_` + 40 url-safe characters.
pub fn generate_api_key() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let body: String = (0..40).map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char).collect();
    format!("pm_{body}")
}

/// Argon2 is deliberately slow (~tens of ms). Applications that open a new
/// SMTP connection per message would burn a CPU core on hashing alone, so a
/// successful verification is remembered for a short time, keyed by a SHA-256
/// of (user, password, stored-hash). Changing the password in config changes
/// the stored hash and therefore invalidates the cache entry automatically.
pub struct AuthCache {
    ok: Mutex<HashMap<String, Instant>>,
    ttl: Duration,
}

impl AuthCache {
    pub fn new(ttl: Duration) -> Self {
        Self { ok: Mutex::new(HashMap::new()), ttl }
    }

    fn key(user: &str, password: &str, phc: &str) -> String {
        let mut h = Sha256::new();
        h.update(user.as_bytes());
        h.update([0]);
        h.update(password.as_bytes());
        h.update([0]);
        h.update(phc.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    pub async fn verify(&self, user: &str, password: &str, phc: &str) -> bool {
        let key = Self::key(user, password, phc);
        if let Some(t) = self.ok.lock().get(&key) {
            if t.elapsed() < self.ttl {
                return true;
            }
        }
        let (pw, ph) = (password.to_string(), phc.to_string());
        let ok = tokio::task::spawn_blocking(move || verify_password(&pw, &ph)).await.unwrap_or(false);
        if ok {
            let mut map = self.ok.lock();
            if map.len() > 10_000 {
                let ttl = self.ttl;
                map.retain(|_, t| t.elapsed() < ttl);
            }
            map.insert(key, Instant::now());
        }
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip() {
        let h = hash_password("s3cret").unwrap();
        assert!(verify_password("s3cret", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("s3cret", "garbage"));
    }

    #[test]
    fn api_key_format() {
        let k = generate_api_key();
        assert!(k.starts_with("pm_") && k.len() == 43);
        assert_eq!(sha256_hex(b"abc").len(), 64);
    }
}
