//! Server certificates from the Windows certificate store (`LocalMachine\<store>`).
//!
//! The private key never leaves CNG: rustls asks a `SigningKey` to sign each handshake
//! and the request is forwarded to `NCryptSignHash`, so non-exportable, TPM- and
//! HSM-backed keys work exactly as they do for IIS.

use crate::tls::CertInfo;
use anyhow::Result;
use rustls::pki_types::CertificateDer;
use rustls::sign::SigningKey;
use std::sync::Arc;

/// A certificate shown by `promailer cert list`.
pub struct StoreEntry {
    pub info: CertInfo,
    /// A private key exists and the current account can use it.
    pub has_key: bool,
    /// Windows archives a certificate when it is renewed or replaced.
    pub archived: bool,
}

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::{anyhow, bail, Context};
    use rustls_cng::cert::CertContext;
    use rustls_cng::error::CngError;
    use rustls_cng::signer::CngSigningKey;
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CertCloseStore, CertDuplicateCertificateContext, CertEnumCertificatesInStore, CertFindCertificateInStore,
        CertGetCertificateContextProperty, CertOpenStore, CERT_ARCHIVED_PROP_ID, CERT_CONTEXT, CERT_FIND_SHA1_HASH,
        CERT_RENEWAL_PROP_ID, CERT_STORE_ENUM_ARCHIVED_FLAG, CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W,
        CERT_STORE_READONLY_FLAG, CERT_SYSTEM_STORE_LOCAL_MACHINE, CRYPT_INTEGER_BLOB, HCERTSTORE, PKCS_7_ASN_ENCODING,
        X509_ASN_ENCODING,
    };

    const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    /// Renewal links followed from the configured thumbprint (also guards against cycles).
    const MAX_RENEWALS: usize = 16;

    /// A read-only LocalMachine store that also enumerates archived certificates: when
    /// AD CS auto-enrollment renews a certificate it archives the old one, which is
    /// exactly the one the configured thumbprint still points at.
    struct Store {
        handle: HCERTSTORE,
        name: String,
    }

    impl Store {
        fn open(name: &str) -> Result<Self> {
            let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            let flags = CERT_SYSTEM_STORE_LOCAL_MACHINE
                | CERT_STORE_OPEN_EXISTING_FLAG
                | CERT_STORE_READONLY_FLAG
                | CERT_STORE_ENUM_ARCHIVED_FLAG;
            // SAFETY: `wide` is a NUL-terminated UTF-16 string that outlives the call.
            let handle = unsafe { CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, wide.as_ptr().cast()) };
            if handle.is_null() {
                bail!("cannot open certificate store LocalMachine\\{name}: {}", std::io::Error::last_os_error());
            }
            Ok(Self { handle, name: name.to_string() })
        }

        fn find_sha1(&self, hash: &[u8]) -> Option<CertContext> {
            let blob = CRYPT_INTEGER_BLOB { cbData: hash.len() as u32, pbData: hash.as_ptr().cast_mut() };
            // SAFETY: the blob points at `hash`, which outlives the call; the returned
            // context is owned by us and released by CertContext's Drop.
            let ctx = unsafe {
                CertFindCertificateInStore(
                    self.handle,
                    ENCODING,
                    0,
                    CERT_FIND_SHA1_HASH,
                    ptr::from_ref(&blob).cast(),
                    ptr::null(),
                )
            };
            (!ctx.is_null()).then(|| CertContext::new_owned(ctx))
        }

        fn all(&self) -> Vec<CertContext> {
            let mut out = Vec::new();
            let mut prev: *const CERT_CONTEXT = ptr::null();
            loop {
                // SAFETY: `prev` is null or the context returned by the previous call,
                // which this call releases; we keep our own duplicated reference.
                let ctx = unsafe { CertEnumCertificatesInStore(self.handle, prev) };
                if ctx.is_null() {
                    break;
                }
                out.push(CertContext::new_owned(unsafe { CertDuplicateCertificateContext(ctx) }));
                prev = ctx;
            }
            out
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            // SAFETY: the handle came from CertOpenStore and is closed once.
            unsafe { CertCloseStore(self.handle, 0) };
        }
    }

    fn property(cert: &CertContext, id: u32) -> Option<Vec<u8>> {
        let mut len = 0u32;
        // SAFETY: standard two-call pattern; the buffer is sized by the first call.
        unsafe {
            if CertGetCertificateContextProperty(cert.inner(), id, ptr::null_mut(), &mut len) == 0 {
                return None;
            }
            let mut buf = vec![0u8; len as usize];
            if CertGetCertificateContextProperty(cert.inner(), id, buf.as_mut_ptr().cast(), &mut len) == 0 {
                return None;
            }
            buf.truncate(len as usize);
            Some(buf)
        }
    }

    fn decode_hex(hex: &str) -> Result<Vec<u8>> {
        (0..hex.len())
            .step_by(2)
            .map(|i| hex.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
            .collect::<Option<Vec<u8>>>()
            .with_context(|| format!("invalid thumbprint '{hex}'"))
    }

    fn key_error(e: CngError) -> anyhow::Error {
        const ACCESS_HINT: &str = "grant the service account Read access to the key \
             (certlm.msc > certificate > All Tasks > Manage Private Keys)";
        match e {
            // CRYPT_E_NO_KEY_PROPERTY
            CngError::WindowsError(0x8009_200B) => anyhow!(
                "the certificate has no private key in this store; import the .pfx (with its key) into LocalMachine"
            ),
            // ERROR_ACCESS_DENIED, E_ACCESSDENIED, NTE_PERM
            CngError::WindowsError(5 | 0x8007_0005 | 0x8009_0010) => {
                anyhow!("access to the private key was denied; {ACCESS_HINT}")
            }
            // NTE_BAD_KEYSET
            CngError::WindowsError(0x8009_0016) => anyhow!(
                "the private key is missing or unreadable (error 0x80090016); re-import the .pfx, or {ACCESS_HINT}"
            ),
            other => anyhow!("cannot open the private key ({other}); {ACCESS_HINT}"),
        }
    }

    pub fn load(store: &str, thumbprint: &str) -> Result<(Vec<CertificateDer<'static>>, Arc<dyn SigningKey>)> {
        let hash = decode_hex(thumbprint)?;
        let store = Store::open(store)?;
        let mut cert = store.find_sha1(&hash).with_context(|| {
            format!(
                "certificate {thumbprint} not found in LocalMachine\\{} (list candidates with `promailer cert list`)",
                store.name
            )
        })?;
        for _ in 0..MAX_RENEWALS {
            let Some(next) = property(&cert, CERT_RENEWAL_PROP_ID).and_then(|h| store.find_sha1(&h)) else {
                break;
            };
            cert = next;
        }
        let resolved = crate::tls::thumbprint(cert.as_der());
        if resolved != thumbprint {
            tracing::info!(
                configured = thumbprint,
                using = %resolved,
                "configured TLS certificate has been renewed; using its replacement"
            );
        }
        let key = cert.acquire_key(true).map_err(key_error).with_context(|| format!("certificate {resolved}"))?;
        let key =
            CngSigningKey::new(key).map_err(|e| anyhow!("unsupported private key for certificate {resolved}: {e}"))?;
        // Leaf first, then intermediates. Fall back to the leaf alone if no chain can be built.
        let chain = cert.as_chain_der().ok().filter(|c| !c.is_empty()).unwrap_or_else(|| vec![cert.as_der().to_vec()]);
        Ok((chain.into_iter().map(CertificateDer::from).collect(), Arc::new(key)))
    }

    pub fn list(store: &str) -> Result<Vec<StoreEntry>> {
        let store = Store::open(store)?;
        let source = format!("LocalMachine\\{}", store.name);
        Ok(store
            .all()
            .into_iter()
            .filter_map(|c| {
                Some(StoreEntry {
                    info: CertInfo::parse(c.as_der(), source.clone()).ok()?,
                    has_key: c.acquire_key(true).is_ok(),
                    archived: property(&c, CERT_ARCHIVED_PROP_ID).is_some(),
                })
            })
            .collect())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use anyhow::bail;

    const MSG: &str = "the Windows certificate store is only available on Windows; use [tls] cert/key PEM files";

    pub fn load(_store: &str, _thumbprint: &str) -> Result<(Vec<CertificateDer<'static>>, Arc<dyn SigningKey>)> {
        bail!(MSG)
    }

    pub fn list(_store: &str) -> Result<Vec<StoreEntry>> {
        bail!(MSG)
    }
}

pub use imp::*;
