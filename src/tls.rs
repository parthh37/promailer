//! TLS configuration (rustls, ring backend) and a stream type that can be
//! upgraded in place for STARTTLS on both the server and client side.

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskCx, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub fn load_server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>> {
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
    let cfg = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("certificate and key do not match")?;
    Ok(Arc::new(cfg))
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
