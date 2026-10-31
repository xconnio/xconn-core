//! QUIC ownership and I/O adapters. Transport and WAMP remain in xconn.
use crate::{
    ByteArray, Result, Value,
    callbacks::{authenticator, codec, server_router},
    resources::{ForeignSession, Output, Resource as BridgeResource, get_resource},
    values::{handle_field, session_fields, string_field},
};
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use xconn_core::async_::{
    quic::{Connection, Listener},
    rawsocket::BoxStream,
};

// Used only when the host explicitly owns certificate verification. TLS
// handshake signatures are still checked by Rust before exporting the chain.
#[derive(Debug)]
pub(super) struct HostVerification {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl HostVerification {
    pub(super) fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl rustls::client::danger::ServerCertVerifier for HostVerification {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub(super) enum Resource {
    Empty,
    Connection(Connection),
    Listener(Arc<Listener>),
    Stream {
        read: Mutex<tokio::io::ReadHalf<BoxStream>>,
        write: Mutex<tokio::io::WriteHalf<BoxStream>>,
        closed: tokio::sync::watch::Sender<bool>,
        read_deadline: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
        write_deadline: tokio::sync::watch::Sender<Option<tokio::time::Instant>>,
    },
}

impl Resource {
    pub(super) fn close(&self) {
        match self {
            Self::Empty => {}
            Self::Connection(connection) => connection.close(),
            Self::Listener(listener) => listener.close(),
            Self::Stream { closed, .. } => {
                closed.send_replace(true);
            }
        }
    }
}

pub(super) fn connection(handle: u64) -> Result<Connection> {
    match get_resource(handle)?.as_ref() {
        BridgeResource::Quic(Resource::Connection(connection)) => Ok(connection.clone()),
        _ => Err("expected QUIC connection".into()),
    }
}

// Forwarding consumes the handle so bytes stay in Rust. Concurrent I/O cannot
// be transferred safely; close it and fail rather than racing a reader/writer.
pub(super) fn take_stream(handle: u64) -> Result<BoxStream> {
    let resource = get_resource(handle)?;
    if !matches!(resource.as_ref(), BridgeResource::Quic(Resource::Stream { .. })) {
        return Err("expected native stream".into());
    }
    drop(resource);
    let resource = crate::resources::take_resource(handle)?;
    let mut resource = Arc::try_unwrap(resource).map_err(|resource| {
        resource.close();
        "cannot transfer a stream with active I/O".to_string()
    })?;
    let BridgeResource::Quic(stream) = &mut resource else {
        unreachable!();
    };
    let Resource::Stream {
        read, write, closed, ..
    } = std::mem::replace(stream, Resource::Empty)
    else {
        unreachable!();
    };
    if *closed.borrow() {
        return Err("native stream is closed".into());
    }
    Ok(read.into_inner().unsplit(write.into_inner()))
}

pub(super) fn stream_output(stream: BoxStream, fields: HashMap<String, Value>) -> Output {
    let (read, write) = tokio::io::split(stream);
    let (closed, _) = tokio::sync::watch::channel(false);
    Output::resource(
        BridgeResource::Quic(Resource::Stream {
            read: Mutex::new(read),
            write: Mutex::new(write),
            closed,
            read_deadline: tokio::sync::watch::channel(None).0,
            write_deadline: tokio::sync::watch::channel(None).0,
        }),
        fields,
    )
}

pub(super) async fn dispatch(method: &str, f: HashMap<String, Value>) -> Result<Output> {
    let plain = |value| Ok(Output::plain(value));
    match method {
        "quic_listen" => {
            let router = server_router(&f)?;
            let address = string_field(&f, "address")?
                .parse()
                .map_err(|_| "invalid QUIC address")?;
            let listener = if let Some(Value::List(chain)) = f.get("certificates") {
                let certificates = chain
                    .iter()
                    .map(|value| match value {
                        Value::Bytes(bytes) => Ok(bytes.0.clone()),
                        _ => Err("expected DER certificate".to_string()),
                    })
                    .collect::<Result<Vec<_>>>()?;
                let Some(Value::Bytes(key)) = f.get("private_key") else {
                    return Err("expected DER private key".into());
                };
                Listener::with_certificate(router, address, certificates, key.0.clone()).await
            } else {
                Listener::bind(router, address).await
            }
            .map_err(|e| e.to_string())?;
            listener.enable_connection_notifications();
            let fields = HashMap::from([
                ("address".into(), Value::Str(listener.local_addr.to_string())),
                (
                    "certificate".into(),
                    Value::Bytes(ByteArray(listener.certificate.clone())),
                ),
            ]);
            Ok(Output::resource(
                BridgeResource::Quic(Resource::Listener(Arc::new(listener))),
                fields,
            ))
        }
        "quic_dial" => {
            let mut roots = rustls::RootCertStore::empty();
            if f.get("host_verification") == Some(&Value::Bool(true)) {
                // The host verifies the chain before exposing the connection.
            } else if let Some(Value::Bytes(certificate)) = f.get("certificate") {
                roots
                    .add(rustls::pki_types::CertificateDer::from(certificate.0.clone()))
                    .map_err(|e| e.to_string())?;
            } else if let Some(Value::List(certificates)) = f.get("roots") {
                for certificate in certificates {
                    let Value::Bytes(certificate) = certificate else {
                        return Err("expected DER root certificate".into());
                    };
                    roots
                        .add(rustls::pki_types::CertificateDer::from(certificate.0.clone()))
                        .map_err(|e| e.to_string())?;
                }
            } else {
                roots.add_parsable_certificates(crate::tls::trusted_certificates());
            }
            let mut tls =
                rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| e.to_string())?
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            if f.get("host_verification") == Some(&Value::Bool(true)) {
                tls.dangerous()
                    .set_certificate_verifier(Arc::new(HostVerification::new()));
            }
            tls.alpn_protocols = vec![xconn_core::async_::quic::ALPN.to_vec()];
            let mut config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|e| e.to_string())?,
            ));
            let mut transport = quinn::TransportConfig::default();
            transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
            config.transport_config(Arc::new(transport));
            let addresses = tokio::net::lookup_host(string_field(&f, "address")?)
                .await
                .map_err(|e| e.to_string())?
                .take(8)
                .collect::<Vec<_>>();
            let name = string_field(&f, "server_name")?;
            let mut attempts = tokio::task::JoinSet::new();
            for (index, address) in addresses.into_iter().enumerate() {
                let config = config.clone();
                let name = name.clone();
                attempts.spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(250 * index as u64)).await;
                    Connection::connect(address, &name, config).await
                });
            }
            let mut last_error = "QUIC address resolved to no addresses".to_string();
            let connection = loop {
                match attempts.join_next().await {
                    Some(Ok(Ok(connection))) => break connection,
                    Some(Ok(Err(error))) => last_error = error.to_string(),
                    Some(Err(error)) => last_error = error.to_string(),
                    None => return Err(last_error),
                }
            };
            // Dropping the remaining attempts closes their unclaimed endpoints.
            drop(attempts);
            let certificates = connection
                .connection
                .peer_identity()
                .and_then(|identity| {
                    identity
                        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                        .ok()
                })
                .ok_or("QUIC peer did not supply a certificate chain")?;
            let fields = HashMap::from([(
                "certificates".into(),
                Value::List(
                    certificates
                        .iter()
                        .map(|certificate| Value::Bytes(ByteArray(certificate.to_vec())))
                        .collect(),
                ),
            )]);
            let mut fields = fields;
            fields.insert(
                "local_address".into(),
                Value::Str(connection.local_addr().map_err(|e| e.to_string())?.to_string()),
            );
            fields.insert(
                "remote_address".into(),
                Value::Str(connection.connection.remote_address().to_string()),
            );
            Ok(Output::resource(
                BridgeResource::Quic(Resource::Connection(connection)),
                fields,
            ))
        }
        "quic_session" => {
            let session = connection(handle_field(&f, "handle")?)?
                .open_session(&string_field(&f, "realm")?, codec(&f)?, authenticator(&f)?)
                .await
                .map_err(|e| e.to_string())?;
            let fields = session_fields(session.details());
            Ok(Output::resource(
                BridgeResource::Session(Arc::new(ForeignSession::new(session))),
                fields,
            ))
        }
        "quic_accept_connection" => {
            let resource = get_resource(handle_field(&f, "handle")?)?;
            let BridgeResource::Quic(Resource::Listener(listener)) = resource.as_ref() else {
                return Err("expected QUIC listener".into());
            };
            let accepted = listener.accept_connection().await.ok_or("QUIC listener closed")?;
            let fields = session_fields(&xconn_core::SessionDetails::from_protocol(&accepted.session));
            Ok(Output::resource(
                BridgeResource::Quic(Resource::Connection(accepted.connection)),
                fields,
            ))
        }
        "quic_accept_remote" => {
            let stream = connection(handle_field(&f, "handle")?)?
                .accept_raw()
                .await
                .map_err(|e| e.to_string())?;
            Ok(stream_output(Box::new(stream), HashMap::new()))
        }
        "quic_wait" => {
            connection(handle_field(&f, "handle")?)?.connection.closed().await;
            plain(Value::Null)
        }
        "quic_open" => {
            let stream = connection(handle_field(&f, "handle")?)?
                .open_raw()
                .await
                .map_err(|e| e.to_string())?;
            Ok(stream_output(Box::new(stream), HashMap::new()))
        }
        "quic_accept" => {
            let resource = get_resource(handle_field(&f, "handle")?)?;
            let BridgeResource::Quic(Resource::Listener(listener)) = resource.as_ref() else {
                return Err("expected QUIC listener".into());
            };
            let stream = listener.accept_raw().await.ok_or("QUIC listener closed")?;
            let fields = session_fields(&xconn_core::SessionDetails::from_protocol(&stream.session));
            Ok(stream_output(stream.stream, fields))
        }
        "quic_read" | "quic_write" | "quic_finish" | "quic_deadlines" => {
            let resource = get_resource(handle_field(&f, "handle")?)?;
            let BridgeResource::Quic(Resource::Stream {
                read,
                write,
                closed,
                read_deadline,
                write_deadline,
            }) = resource.as_ref()
            else {
                return Err("expected QUIC stream".into());
            };
            if method == "quic_deadlines" {
                for (key, deadline) in [("read", read_deadline), ("write", write_deadline)] {
                    if let Some(value) = f.get(key) {
                        let timeout = match value {
                            Value::Null => None,
                            Value::Int(timestamp) => Some(*timestamp),
                            Value::UInt(timestamp) => {
                                Some(i64::try_from(*timestamp).map_err(|_| "invalid stream deadline")?)
                            }
                            _ => return Err("expected Unix millisecond deadline or null".into()),
                        };
                        let instant = timeout
                            .map(|timestamp| {
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis();
                                let remaining = u128::try_from(timestamp).unwrap_or(0).saturating_sub(now);
                                tokio::time::Instant::now()
                                    .checked_add(std::time::Duration::from_millis(
                                        u64::try_from(remaining).map_err(|_| "stream deadline is out of range")?,
                                    ))
                                    .ok_or("stream deadline is out of range")
                            })
                            .transpose()?;
                        deadline.send_replace(instant);
                    }
                }
                return plain(Value::Null);
            }
            let deadline = if method == "quic_read" {
                read_deadline
            } else {
                write_deadline
            };
            let mut cancellation = closed.subscribe();
            if *cancellation.borrow() {
                return Err("QUIC stream closed".into());
            }
            let operation = async {
                if method == "quic_read" {
                    let size = usize::try_from(handle_field(&f, "size")?).map_err(|_| "invalid read size")?;
                    if size > 1024 * 1024 {
                        return Err("read size exceeds 1 MiB".into());
                    }
                    let mut bytes = vec![0; size];
                    let count = read.lock().await.read(&mut bytes).await.map_err(|e| e.to_string())?;
                    bytes.truncate(count);
                    plain(Value::Bytes(ByteArray(bytes)))
                } else {
                    let mut writer = write.lock().await;
                    if method == "quic_finish" {
                        writer.shutdown().await.map_err(|e| e.to_string())?;
                    } else {
                        let Some(Value::Bytes(bytes)) = f.get("data") else {
                            return Err("expected stream bytes".into());
                        };
                        let count = writer.write(&bytes.0).await.map_err(|e| e.to_string())?;
                        return plain(Value::UInt(count as u64));
                    }
                    plain(Value::Null)
                }
            };

            tokio::select! {
                biased;
                _ = cancellation.changed() => Err("QUIC stream closed".into()),
                _ = wait_deadline(deadline.subscribe()) => Err("stream deadline exceeded".into()),
                result = operation => result,
            }
        }
        _ => Err(format!("unknown QUIC operation {method}")),
    }
}

// Updating a deadline changes the timer without restarting or cancelling the I/O.
async fn wait_deadline(mut deadline: tokio::sync::watch::Receiver<Option<tokio::time::Instant>>) {
    loop {
        let current = *deadline.borrow_and_update();
        match current {
            Some(instant) => {
                if instant <= tokio::time::Instant::now() {
                    return;
                }
                tokio::select! {
                    _ = tokio::time::sleep_until(instant) => return,
                    result = deadline.changed() => if result.is_err() { return; },
                }
            }
            None => {
                if deadline.changed().await.is_err() {
                    return;
                }
            }
        }
    }
}
