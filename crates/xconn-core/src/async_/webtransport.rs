//! WebTransport HTTP/3 with reliable stream resets required by modern peers.
pub use super::multiplex::AuthenticatedStream;
use super::{joiner::join, rawsocket::client_handshake, router::Router, session::Session};
use crate::{Error, SerializerSpec};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc, watch},
};
pub use webtrans_quion as backend;
pub type ClientConfig = backend::Client;

pub struct Stream {
    send: backend::SendStream,
    recv: backend::RecvStream,
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
        Pin::new(&mut self.send).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

#[derive(Clone)]
pub struct Connection {
    pub connection: backend::Session,
    _client: backend::Client,
}

/// A TLS connection and the identity of the endpoint that completed its handshake.
pub struct TlsConnection {
    pub connection: Connection,
    pub certificates: Vec<Vec<u8>>,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

impl Connection {
    pub async fn connect(url: &str, config: ClientConfig) -> Result<Self, Error> {
        let url = url::Url::parse(url).map_err(|e| Error::new(e.to_string()))?;
        let connection = config.connect(url).await.map_err(|e| Error::new(e.to_string()))?;
        Ok(Self {
            connection,
            _client: config,
        })
    }

    /// Dial with application-configured TLS and try both DNS address families.
    /// Each attempt owns its endpoint; dropping a losing attempt releases it.
    pub async fn connect_with_tls(url: &str, mut tls: rustls::ClientConfig) -> Result<TlsConnection, Error> {
        let url = url::Url::parse(url).map_err(|e| Error::new(e.to_string()))?;
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some()
        {
            return Err(Error::new(
                "WebTransport requires an https URL without userinfo or fragment",
            ));
        }
        let name = url
            .host_str()
            .ok_or_else(|| Error::new("missing WebTransport host"))?
            .trim_matches(['[', ']'])
            .to_owned();
        let addresses = tokio::net::lookup_host((name.as_str(), url.port().unwrap_or(443)))
            .await
            .map_err(|e| Error::new(e.to_string()))?
            .take(8)
            .collect::<Vec<_>>();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut transport = backend::quion::TransportConfig::default();
        transport
            .set_reset_stream_at(true)
            .set_max_datagram_frame_size(Some(backend::quion::VarInt::from_u32(65_535)));
        let config = backend::quion::ClientConfig::builder()
            .with_rustls_config(tls)
            .with_transport_config(transport.clone())
            .build();
        let mut attempts = tokio::task::JoinSet::new();
        for (index, address) in addresses.into_iter().enumerate() {
            let config = config.clone();
            let transport = transport.clone();
            let name = name.clone();
            let url = url.clone();
            attempts.spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(250 * index as u64)).await;
                let local = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                let endpoint = backend::quion::Endpoint::client_with_config(
                    backend::quion::EndpointConfig { transport },
                    local.parse().unwrap(),
                )
                .map_err(|e| Error::new(e.to_string()))?;
                let local_addr = endpoint.local_addr();
                let client = backend::Client::new(endpoint.clone(), config);
                let connection = endpoint
                    .connect(address, &name)
                    .map_err(|e| Error::new(e.to_string()))?
                    .await
                    .map_err(|e| Error::new(e.to_string()))?;
                let certificates = connection
                    .peer_certificates()
                    .ok_or_else(|| Error::new("missing WebTransport peer certificates"))?;
                let connection = backend::Session::connect(connection, url)
                    .await
                    .map_err(|e| Error::new(e.to_string()))?;
                Ok::<_, Error>(TlsConnection {
                    connection: Self {
                        connection,
                        _client: client,
                    },
                    certificates,
                    local_addr,
                    remote_addr: address,
                })
            });
        }
        let mut last_error = Error::new("WebTransport address resolved to no addresses");
        while let Some(result) = attempts.join_next().await {
            match result {
                Ok(Ok(connection)) => return Ok(connection),
                Ok(Err(error)) => last_error = error,
                Err(error) => last_error = Error::new(error.to_string()),
            }
        }
        Err(last_error)
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
        self.connection.close(0, b"");
    }
}

pub struct Listener {
    pub local_addr: SocketAddr,
    pub certificate: Vec<u8>,
    raw: Mutex<mpsc::Receiver<AuthenticatedStream>>,
    connections: Arc<StdMutex<Vec<backend::Session>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.close();
    }
}

impl Listener {
    pub async fn bind(router: Router, addr: SocketAddr) -> Result<Self, Error> {
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(|e| Error::new(e.to_string()))?;
        let certificate = generated.cert.der().to_vec();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der());
        let mut transport = backend::quion::TransportConfig::default();
        transport
            .set_reset_stream_at(true)
            .set_max_datagram_frame_size(Some(backend::quion::VarInt::from_u32(65_535)))
            .set_retry_enabled(false)
            .set_max_connections(1024)
            .set_max_pending_handshakes(256)
            .set_max_endpoint_memory_bytes(64 * 1024 * 1024);
        let server = backend::ServerBuilder::new()
            .with_transport_config(transport)
            .with_addr(addr)
            .with_handshake_timeout(std::time::Duration::from_secs(10))
            .with_max_pending_handshakes(std::num::NonZeroUsize::new(256).unwrap())
            .with_certificate(vec![generated.cert.der().clone()], key.into())
            .map_err(|e| Error::new(e.to_string()))?;
        Self::with_server(router, server, certificate).await
    }

    pub async fn with_server(router: Router, server: backend::Server, certificate: Vec<u8>) -> Result<Self, Error> {
        Self::with_server_path(router, server, certificate, None).await
    }

    /// Restrict CONNECT requests to the configured path before accepting a session.
    pub async fn with_server_path(
        router: Router,
        mut server: backend::Server,
        certificate: Vec<u8>,
        path: Option<String>,
    ) -> Result<Self, Error> {
        let local_addr = server.local_addr().map_err(|e| Error::new(e.to_string()))?;
        let (tx, raw) = mpsc::channel(64);
        let connections = Arc::new(StdMutex::new(Vec::<backend::Session>::new()));
        let peers = connections.clone();
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();

            loop {
                tokio::select! {
                    request = server.accept() => {
                        let request = match request {
                            Some(Ok(request)) => request,
                            Some(Err(_)) => continue,
                            None => break,
                        };
                        if path.as_ref().is_some_and(|path| request.url().path() != path) {
                            // Dropping a request rejects it without exposing WAMP or raw streams.
                            drop(request);
                            continue;
                        }
                        let router = router.clone();
                        let raw = tx.clone();
                        let peers = peers.clone();
                        handlers.spawn(async move {
                            let Ok(connection) = request.ok().await else {
                                return;
                            };
                            {
                                let mut peers = peers.lock().unwrap();
                                peers.retain(|peer| peer.close_reason().is_none());
                                peers.push(connection.clone());
                            }

                            let (authenticated, mut identity) = watch::channel(None::<wampproto::types::SessionDetails>);
                            let mut announced = false;
                            #[cfg(feature = "services")]
                            let mut _destination = None;
                            let mut streams = tokio::task::JoinSet::new();

                            loop {
                                tokio::select! {
                                    changed = identity.changed(), if !announced => {
                                        if changed.is_err() { break; }
                                        if let Some(session) = identity.borrow_and_update().clone() {
                                            announced = true;
                                            #[cfg(not(feature = "services"))]
                                            let _ = session;
                                            #[cfg(feature = "services")]
                                            if let Some(routing) = router.stream_routing() {
                                                let target = connection.clone();
                                                _destination = match routing.register(session, Arc::new(move || {
                                                    let target = target.clone();
                                                    Box::pin(async move {
                                                        let (send, recv) = target.open_bi().await
                                                            .map_err(|error| Error::new(error.to_string()))?;
                                                        Ok(Box::new(Stream { send, recv }) as super::rawsocket::BoxStream)
                                                    })
                                                })) {
                                                    Ok(registration) => registration,
                                                    Err(_) => {
                                                        connection.close(0, b"");
                                                        break;
                                                    }
                                                };
                                            }
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
                    Some(_) = handlers.join_next(), if !handlers.is_empty() => {}
                }
            }
        });
        Ok(Self {
            local_addr,
            certificate,
            raw: Mutex::new(raw),
            connections,
            task,
        })
    }

    pub async fn accept_raw(&self) -> Option<AuthenticatedStream> {
        self.raw.lock().await.recv().await
    }

    pub fn close(&self) {
        for peer in self.connections.lock().unwrap().drain(..) {
            peer.close(0, b"");
        }

        self.task.abort();
    }

    pub fn client_config(&self) -> Result<ClientConfig, Error> {
        backend::ClientBuilder::new()
            .with_handshake_timeout(std::time::Duration::from_secs(10))
            .with_server_certificates(vec![rustls::pki_types::CertificateDer::from(self.certificate.clone())])
            .map_err(|e| Error::new(e.to_string()))
    }
}
