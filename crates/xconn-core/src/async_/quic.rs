//! WAMP and authenticated raw streams over QUIC (ALPN wamp.2.quic).
pub use super::multiplex::AuthenticatedStream;
use super::{joiner::join, rawsocket::client_handshake, router::Router, session::Session};
use crate::{Error, SerializerSpec};
use std::{net::SocketAddr, sync::Arc};
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc, watch},
    task::JoinHandle,
};
pub const ALPN: &[u8] = b"wamp.2.quic";

pub struct Stream {
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

#[derive(Clone)]
pub struct Connection {
    pub connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

impl Connection {
    pub async fn connect(addr: SocketAddr, name: &str, config: quinn::ClientConfig) -> Result<Self, Error> {
        let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let mut endpoint = quinn::Endpoint::client(bind.parse().unwrap()).map_err(|e| Error::new(e.to_string()))?;
        endpoint.set_default_client_config(config);
        let connection = endpoint
            .connect(addr, name)
            .map_err(|e| Error::new(e.to_string()))?
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        Ok(Self {
            connection,
            _endpoint: endpoint,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, Error> {
        self._endpoint.local_addr().map_err(|e| Error::new(e.to_string()))
    }

    pub async fn open_raw(&self) -> Result<Stream, Error> {
        let (send, recv) = self.connection.open_bi().await.map_err(|e| Error::new(e.to_string()))?;
        Ok(Stream { send, recv })
    }

    pub async fn accept_raw(&self) -> Result<Stream, Error> {
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| Error::new(e.to_string()))?;
        Ok(Stream { send, recv })
    }

    pub async fn open_session(
        &self,
        realm: &str,
        spec: Box<dyn SerializerSpec>,
        auth: Box<dyn wampproto::authenticators::authenticator::ClientAuthenticator + Send + Sync>,
    ) -> Result<Session, Error> {
        let stream = self.open_raw().await?;
        let peer = client_handshake(Box::new(stream), spec.serializer_id()).await?;
        let (peer, details) = join(peer, realm, spec.serializer(), auth).await?;
        Ok(Session::new(details, peer, spec.serializer()))
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"");
    }
}

/// Run a backend over one QUIC connection per attempt. The handler restores RPC
/// registrations and may accept raw streams. Returning an error stops the backend;
/// return Ok on normal stream EOF. Cancelling this future closes the connection.
#[cfg(feature = "services")]
pub async fn run_backend<F, Fut>(
    address: SocketAddr,
    server_name: &str,
    tls: quinn::ClientConfig,
    realm: &str,
    client: super::client::Client,
    handler: F,
) -> Result<(), Error>
where
    F: Fn(Session, Connection) -> Fut,
    Fut: Future<Output = Result<(), Error>>,
{
    struct Owner(Connection);

    impl Drop for Owner {
        fn drop(&mut self) {
            self.0.close();
        }
    }

    super::services::backend::run(
        || async {
            let connection = Arc::new(Owner(Connection::connect(address, server_name, tls.clone()).await?));
            let session = connection
                .0
                .open_session(realm, client.serializer.clone(), client.authenticator.clone())
                .await?;
            Ok((session, connection))
        },
        |session, connection| handler(session, connection.0.clone()),
    )
    .await
}

pub struct AuthenticatedConnection {
    pub connection: Connection,
    pub session: wampproto::types::SessionDetails,
}

pub struct Listener {
    pub local_addr: SocketAddr,
    pub certificate: Vec<u8>,
    raw: Mutex<mpsc::Receiver<AuthenticatedStream>>,
    authenticated: Mutex<mpsc::Receiver<AuthenticatedConnection>>,
    notifications_enabled: Arc<std::sync::atomic::AtomicBool>,
    endpoint: quinn::Endpoint,
    task: JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
        self.task.abort();
    }
}

impl Listener {
    pub async fn bind(router: Router, addr: SocketAddr) -> Result<Self, Error> {
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| Error::new(e.to_string()))?;
        let certificate = generated.cert.der().to_vec();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::new(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(vec![generated.cert.der().clone()], key.into())
            .map_err(|e| Error::new(e.to_string()))?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| Error::new(e.to_string()))?,
        ));
        Self::with_config(router, addr, config, certificate).await
    }

    pub async fn with_certificate(
        router: Router,
        addr: SocketAddr,
        certificates: Vec<Vec<u8>>,
        private_key: Vec<u8>,
    ) -> Result<Self, Error> {
        let certificate = certificates
            .first()
            .cloned()
            .ok_or_else(|| Error::new("empty certificate chain"))?;
        let key = rustls::pki_types::PrivateKeyDer::try_from(private_key).map_err(Error::new)?;
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::new(e.to_string()))?
            .with_no_client_auth()
            .with_single_cert(
                certificates
                    .into_iter()
                    .map(rustls::pki_types::CertificateDer::from)
                    .collect(),
                key,
            )
            .map_err(|e| Error::new(e.to_string()))?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|e| Error::new(e.to_string()))?,
        ));
        Self::with_config(router, addr, config, certificate).await
    }

    pub async fn with_config(
        router: Router,
        addr: SocketAddr,
        config: quinn::ServerConfig,
        certificate: Vec<u8>,
    ) -> Result<Self, Error> {
        let endpoint = quinn::Endpoint::server(config, addr).map_err(|e| Error::new(e.to_string()))?;
        let local_addr = endpoint.local_addr().map_err(|e| Error::new(e.to_string()))?;
        let incoming = endpoint.clone();
        let (tx, raw) = mpsc::channel(64);
        let (notifications, authenticated_connections) = mpsc::channel(64);
        let notifications_enabled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let enabled = notifications_enabled.clone();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();

            loop {
                tokio::select! {
                    connection = incoming.accept() => {
                        let Some(connection) = connection else { break };
                        let router = router.clone();
                        let raw = tx.clone();
                        let notifications = notifications.clone();
                        let enabled = enabled.clone();
                        let endpoint = incoming.clone();
                        connections.spawn(async move {
                            let Ok(connection) = connection.await else {
                                return;
                            };
                            let (authenticated, mut identity) = watch::channel(None::<wampproto::types::SessionDetails>);
                            let accepted = Connection { connection: connection.clone(), _endpoint: endpoint };
                            let mut announced = false;
                            #[cfg(feature = "services")]
                            let mut _destination = None;
                            let mut streams = tokio::task::JoinSet::new();

                            loop {
                                tokio::select! {
                                    changed = identity.changed(), if !announced => {
                                        if changed.is_err() { break; }
                                        let session = identity.borrow_and_update().clone();
                                        if let Some(session) = session {
                                            #[cfg(feature = "services")]
                                            let mut managed = false;
                                            #[cfg(not(feature = "services"))]
                                            let managed = false;
                                            #[cfg(feature = "services")]
                                            if let Some(routing) = router.stream_routing() {
                                                managed = true;
                                                let connection = accepted.clone();
                                                _destination = match routing.register(session.clone(), Arc::new(move || {
                                                    let connection = connection.clone();
                                                    Box::pin(async move {
                                                        let stream = connection.open_raw().await?;
                                                        Ok(Box::new(stream) as super::rawsocket::BoxStream)
                                                    })
                                                })) {
                                                    Ok(registration) => registration,
                                                    Err(_) => {
                                                        accepted.close();
                                                        break;
                                                    }
                                                };
                                            }
                                            if !managed && enabled.load(std::sync::atomic::Ordering::Acquire) {
                                                let event = AuthenticatedConnection { connection: accepted.clone(), session };
                                                tokio::select! {
                                                    result = notifications.send(event) => {
                                                        if result.is_err() { break; }
                                                    }
                                                    _ = connection.closed() => break,
                                                }
                                            }
                                            announced = true;
                                        }
                                    }
                                    incoming = connection.accept_bi() => {
                                        let Ok((send, recv)) = incoming else { break };
                                        let router = router.clone();
                                        let raw = raw.clone();
                                        let auth = authenticated.clone();
                                        streams.spawn(async move {
                                            let _ = super::multiplex::serve_stream(
                                                router,
                                                Box::new(Stream { send, recv }),
                                                auth,
                                                raw,
                                            )
                                                .await;
                                        });
                                    }
                                    Some(_) = streams.join_next(), if !streams.is_empty() => {}
                                }
                            }
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });
        Ok(Self {
            local_addr,
            certificate,
            raw: Mutex::new(raw),
            authenticated: Mutex::new(authenticated_connections),
            notifications_enabled,
            endpoint,
            task,
        })
    }

    /// Enable bounded authenticated-connection events before accepting clients.
    pub fn enable_connection_notifications(&self) {
        self.notifications_enabled
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub async fn accept_connection(&self) -> Option<AuthenticatedConnection> {
        self.authenticated.lock().await.recv().await
    }

    pub async fn accept_raw(&self) -> Option<AuthenticatedStream> {
        self.raw.lock().await.recv().await
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"");
    }

    pub fn client_config(&self) -> Result<quinn::ClientConfig, Error> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(self.certificate.clone()))
            .map_err(|e| Error::new(e.to_string()))?;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| Error::new(e.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        Ok(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| Error::new(e.to_string()))?,
        )))
    }
}
