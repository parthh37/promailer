//! TLS configuration (rustls, ring backend) and a stream type that can be
//! upgraded in place for STARTTLS on both the server and client side.

use crate::config::{TlsConfig, TlsSource};
use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCx, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A loaded server certificate: the rustls configuration plus details for logs and checks.
pub struct ServerCert {
    pub config: Arc<ServerConfig>,
    pub info: CertInfo,
}

/// Identity and validity of the leaf certificate, whatever its source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// File path, or `LocalMachine\<store>` for the Windows certificate store.
    pub source: String,
    /// SHA-1 thumbprint in upper-case hex, the form certlm.msc and PowerShell display.
    pub thumbprint: String,
    pub subject: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl CertInfo {
    pub fn parse(der: &[u8], source: String) -> Result<Self> {
        use x509_cert::der::Decode;
        let cert = x509_cert::Certificate::from_der(der).context("parsing X.509 certificate")?;
        let tbs = &cert.tbs_certificate;
        let time = |t: &x509_cert::time::Time| {
            DateTime::from_timestamp(t.to_unix_duration().as_secs() as i64, 0).unwrap_or_default()
        };
        Ok(Self {
            source,
            thumbprint: thumbprint(der),
            subject: tbs.subject.to_string(),
            not_before: time(&tbs.validity.not_before),
            not_after: time(&tbs.validity.not_after),
        })
    }

    pub fn health(&self, now: DateTime<Utc>) -> CertHealth {
        assess_validity(self.not_before, self.not_after, now)
    }
}

/// SHA-1 over the DER encoding: what Windows calls the certificate thumbprint.
pub fn thumbprint(der: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, der);
    digest.as_ref().iter().map(|b| format!("{b:02X}")).collect()
}

/// Outcome of checking a certificate's validity window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertHealth {
    /// Nothing to report.
    Healthy,
    /// Keep using the certificate but raise a warning (Event Log ID 1010).
    Warn(String),
    /// Refuse the certificate when loading it: start-up fails, or a reload keeps the
    /// previous certificate. If it is already in use, raise an error (Event Log ID 1011).
    Reject(String),
}

/// Policy for a certificate's validity window. Called when the certificate is loaded
/// (start-up, reload, renewal pick-up) and once a day while it is in use.
pub fn assess_validity(not_before: DateTime<Utc>, not_after: DateTime<Utc>, now: DateTime<Utc>) -> CertHealth {
    // TODO(policy): decide how Promailer treats expired, not-yet-valid and soon-to-expire
    // certificates. See the request in the conversation for the trade-offs.
    let _ = (not_before, not_after, now);
    CertHealth::Healthy
}

/// Load the configured server certificate from PEM files or the Windows certificate store.
pub fn load_server(cfg: &TlsConfig) -> Result<ServerCert> {
    let provider = provider();
    let (certified, source) = match cfg.source()? {
        TlsSource::Files { cert, key } => (load_pem(cert, key, &provider)?, cert.display().to_string()),
        TlsSource::Store { store, thumbprint } => {
            let (chain, key) = crate::certstore::load(store, thumbprint)?;
            (CertifiedKey::new(chain, key), format!("LocalMachine\\{store}"))
        }
    };
    let info = CertInfo::parse(certified.end_entity_cert()?, source)?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    Ok(ServerCert { config: Arc::new(config), info })
}

fn load_pem(cert: &Path, key: &Path, provider: &CryptoProvider) -> Result<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> = {
        let data = std::fs::read(cert).with_context(|| format!("reading {}", cert.display()))?;
        rustls_pemfile::certs(&mut data.as_slice())
            .collect::<Result<_, _>>()
            .with_context(|| format!("parsing certificates in {}", cert.display()))?
    };
    if certs.is_empty() {
        bail!("no certificates found in {}", cert.display());
    }
    let key: PrivateKeyDer<'static> = {
        let data = std::fs::read(key).with_context(|| format!("reading {}", key.display()))?;
        rustls_pemfile::private_key(&mut data.as_slice())
            .with_context(|| format!("parsing private key in {}", key.display()))?
            .with_context(|| format!("no private key found in {}", key.display()))?
    };
    CertifiedKey::from_der(certs, key, provider).context("certificate and key do not match")
}

pub fn acceptor(cfg: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(cfg)
}

/// Client TLS configs: one verifying against Mozilla roots, one accepting any
/// certificate (opportunistic MTA-to-MTA TLS, where self-signed certs are common
/// and encryption without authentication still beats plain text).
pub struct ClientTls {
    pub verifying: TlsConnector,
    pub insecure: TlsConnector,
}

impl ClientTls {
    pub fn new() -> Result<Self> {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let verifying = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let insecure = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert(provider())))
            .with_no_client_auth();
        Ok(Self {
            verifying: TlsConnector::from(Arc::new(verifying)),
            insecure: TlsConnector::from(Arc::new(insecure)),
        })
    }
}

#[derive(Debug)]
struct AcceptAnyCert(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Stream
// ---------------------------------------------------------------------------

pub enum Stream {
    Plain(TcpStream),
    ServerTls(Box<tokio_rustls::server::TlsStream<TcpStream>>),
    ClientTls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// Placeholder while the real socket is moved into a TLS handshake.
    Detached,
}

fn detached() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "stream detached")
}

impl Stream {
    /// Negotiated protocol and cipher, for Received headers and logs.
    pub fn tls_info(&self) -> Option<String> {
        let (ver, suite) = match self {
            Stream::Plain(_) | Stream::Detached => return None,
            Stream::ServerTls(s) => {
                let c = s.get_ref().1;
                (c.protocol_version(), c.negotiated_cipher_suite())
            }
            Stream::ClientTls(s) => {
                let c = s.get_ref().1;
                (c.protocol_version(), c.negotiated_cipher_suite())
            }
        };
        let ver = ver.map(|v| format!("{v:?}").replace('_', ".")).unwrap_or_default();
        let suite = suite.map(|s| format!("{:?}", s.suite())).unwrap_or_default();
        Some(format!("{ver} {suite}").trim().to_string())
    }

    pub async fn upgrade_server(self, acceptor: &TlsAcceptor) -> io::Result<Stream> {
        match self {
            Stream::Plain(tcp) => Ok(Stream::ServerTls(Box::new(acceptor.accept(tcp).await?))),
            _ => Err(io::Error::other("stream already uses TLS")),
        }
    }

    pub async fn upgrade_client(self, connector: &TlsConnector, host: &str) -> io::Result<Stream> {
        match self {
            Stream::Plain(tcp) => {
                let name = ServerName::try_from(host.to_string())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TLS server name"))?;
                Ok(Stream::ClientTls(Box::new(connector.connect(name, tcp).await?)))
            }
            _ => Err(io::Error::other("stream already uses TLS")),
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::ServerTls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Stream::ClientTls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Stream::Detached => Poll::Ready(Err(detached())),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskCx<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            Stream::ServerTls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Stream::ClientTls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Stream::Detached => Poll::Ready(Err(detached())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::ServerTls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Stream::ClientTls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Stream::Detached => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskCx<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::ServerTls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Stream::ClientTls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Stream::Detached => Poll::Ready(Ok(())),
        }
    }
}
