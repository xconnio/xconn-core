#![cfg(feature = "services")]

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
};
use xconn_core::{
    async_::{
        rawsocket::BoxStream,
        services::stream_broker::{StreamBroker, StreamOpener},
    },
    wampproto::types::SessionDetails,
};

fn identity(authid: &str, role: &str, realm: &str) -> SessionDetails {
    SessionDetails::new(1, realm.into(), authid.into(), role.into(), false)
}

fn opener(marker: u8, opened: Arc<AtomicUsize>) -> StreamOpener {
    Arc::new(move || {
        opened.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            let (stream, mut peer) = tokio::io::duplex(16);
            peer.write_all(&[marker]).await.unwrap();
            Ok(Box::new(stream) as BoxStream)
        })
    })
}

#[tokio::test]
async fn policy_checks_trusted_source_and_destination_before_opening() {
    let opened = Arc::new(AtomicUsize::new(0));
    let broker = StreamBroker::new(Arc::new(|source, key, target| {
        key == "backend" && source.realm == target.realm && source.auth_role == "operator"
    }));
    let registration = broker
        .register(
            "backend",
            identity("service", "backend", "tenant"),
            opener(7, opened.clone()),
        )
        .unwrap();
    for source in [
        identity("alice", "guest", "tenant"),
        identity("alice", "operator", "other-tenant"),
    ] {
        assert!(broker.open(&source, "backend").await.is_err());
    }
    assert_eq!(opened.load(Ordering::SeqCst), 0);
    let mut stream = broker
        .open(&identity("alice", "operator", "tenant"), "backend")
        .await
        .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), 7);
    assert_eq!(opened.load(Ordering::SeqCst), 1);
    registration.close();
    assert!(
        broker
            .open(&identity("alice", "operator", "tenant"), "backend")
            .await
            .is_err()
    );
    assert_eq!(opened.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn an_old_connection_cannot_unregister_its_replacement() {
    let opened = Arc::new(AtomicUsize::new(0));
    let broker = StreamBroker::new(Arc::new(|_, _, _| true));
    let old = broker
        .register(
            "backend",
            identity("old", "backend", "tenant"),
            opener(1, opened.clone()),
        )
        .unwrap();
    let current = broker
        .register("backend", identity("new", "backend", "tenant"), opener(2, opened))
        .unwrap();
    drop(old);
    let mut stream = broker
        .open(&identity("alice", "operator", "tenant"), "backend")
        .await
        .unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), 2);
    drop(current);
    assert!(
        broker
            .open(&identity("alice", "operator", "tenant"), "backend")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn relay_drains_a_large_reply_after_the_request_half_closes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, incoming) = tokio::io::duplex(32);
        let (outgoing, mut backend) = tokio::io::duplex(32);
        let stream = Arc::new(Mutex::new(Some(outgoing)));
        let broker = StreamBroker::new(Arc::new(|_, _, _| true));
        let registration = broker
            .register(
                "backend",
                identity("service", "backend", "tenant"),
                Arc::new(move || {
                    let stream = stream.lock().unwrap().take().unwrap();
                    Box::pin(async move { Ok(Box::new(stream) as BoxStream) })
                }),
            )
            .unwrap();
        let relay = tokio::spawn(async move {
            broker
                .relay(&identity("alice", "operator", "tenant"), "backend", Box::new(incoming))
                .await
        });
        let request = async {
            client.write_all(b"hello").await.unwrap();
            client.shutdown().await.unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, vec![42; 128 * 1024]);
        };
        let response = async {
            let mut request = Vec::new();
            backend.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"hello");
            backend.write_all(&vec![42; 128 * 1024]).await.unwrap();
            backend.shutdown().await.unwrap();
        };
        tokio::join!(request, response);
        assert_eq!(relay.await.unwrap().unwrap(), (5, 128 * 1024));
        drop(registration);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_a_relay_releases_both_streams() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, incoming) = tokio::io::duplex(32);
        let (outgoing, mut backend) = tokio::io::duplex(32);
        let stream = Arc::new(Mutex::new(Some(outgoing)));
        let (opened, observed) = oneshot::channel();
        let opened = Mutex::new(Some(opened));
        let broker = StreamBroker::new(Arc::new(|_, _, _| true));
        let registration = broker
            .register(
                "backend",
                identity("service", "backend", "tenant"),
                Arc::new(move || {
                    let stream = stream.lock().unwrap().take().unwrap();
                    opened.lock().unwrap().take().unwrap().send(()).unwrap();
                    Box::pin(async move { Ok(Box::new(stream) as BoxStream) })
                }),
            )
            .unwrap();
        let relay = tokio::spawn(async move {
            broker
                .relay(&identity("alice", "operator", "tenant"), "backend", Box::new(incoming))
                .await
        });
        observed.await.unwrap();
        relay.abort();
        assert!(relay.await.unwrap_err().is_cancelled());
        assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
        assert_eq!(backend.read(&mut [0]).await.unwrap(), 0);
        drop(registration);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_an_open_releases_the_pending_connector() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (started, entered) = oneshot::channel();
        let (finish, finished) = oneshot::channel::<()>();
        let channels = Mutex::new(Some((started, finished)));
        let broker = StreamBroker::new(Arc::new(|_, _, _| true));
        let registration = broker
            .register(
                "backend",
                identity("service", "backend", "tenant"),
                Arc::new(move || {
                    let (started, finished) = channels.lock().unwrap().take().unwrap();
                    Box::pin(async move {
                        started.send(()).unwrap();
                        finished.await.unwrap();
                        let (stream, _) = tokio::io::duplex(16);
                        Ok(Box::new(stream) as BoxStream)
                    })
                }),
            )
            .unwrap();
        let opening =
            tokio::spawn(async move { broker.open(&identity("alice", "operator", "tenant"), "backend").await });
        entered.await.unwrap();
        opening.abort();
        assert!(opening.await.err().unwrap().is_cancelled());
        assert!(finish.is_closed());
        drop(registration);
    })
    .await
    .unwrap();
}

#[cfg(feature = "quic")]
#[tokio::test]
async fn broker_relays_between_authenticated_quic_connections() {
    use xconn_core::{
        JSONSerializerSpec,
        async_::{
            quic::{Connection, Listener},
            router::{RealmConfig, Router},
        },
        wampproto::authenticators::anonymous::AnonymousAuthenticator,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        let router = Router::new();
        router.add_realm("example", RealmConfig::default()).unwrap();
        let listener = Listener::bind(router.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        listener.enable_connection_notifications();
        let backend = Connection::connect(listener.local_addr, "localhost", listener.client_config().unwrap())
            .await
            .unwrap();
        let backend_session = backend
            .open_session(
                "example",
                Box::new(JSONSerializerSpec),
                Box::new(AnonymousAuthenticator::default()),
            )
            .await
            .unwrap();
        let destination = listener.accept_connection().await.unwrap();
        let broker = StreamBroker::new(Arc::new(|source, _, target| source.realm == target.realm));
        let registration = broker
            .register(
                "service",
                destination.session,
                Arc::new(move || {
                    let connection = destination.connection.clone();
                    Box::pin(async move { Ok(Box::new(connection.open_raw().await?) as BoxStream) })
                }),
            )
            .unwrap();
        let client = Connection::connect(listener.local_addr, "localhost", listener.client_config().unwrap())
            .await
            .unwrap();
        let client_session = client
            .open_session(
                "example",
                Box::new(JSONSerializerSpec),
                Box::new(AnonymousAuthenticator::default()),
            )
            .await
            .unwrap();
        let mut request = client.open_raw().await.unwrap();
        request.write_all(b"hello").await.unwrap();
        request.shutdown().await.unwrap();
        let incoming = listener.accept_raw().await.unwrap();
        assert_eq!(incoming.session.id, client_session.details().id());
        let relay = tokio::spawn(async move { broker.relay(&incoming.session, "service", incoming.stream).await });
        let mut response = backend.accept_raw().await.unwrap();
        let mut body = Vec::new();
        response.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"hello");
        response.write_all(b"world").await.unwrap();
        response.shutdown().await.unwrap();
        let mut reply = Vec::new();
        request.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"world");
        assert_eq!(relay.await.unwrap().unwrap(), (5, 5));
        drop(registration);
        client_session.close().await.unwrap();
        backend_session.close().await.unwrap();
        client.close();
        backend.close();
        listener.close();
        router.close();
    })
    .await
    .unwrap();
}

#[cfg(feature = "quic")]
#[tokio::test]
async fn configured_router_owns_stream_registration_and_forwarding() {
    use xconn_core::{
        Error, JSONSerializerSpec,
        async_::{
            quic::{Connection, Listener},
            router::{RealmConfig, Router},
            services::routing::StreamRouting,
        },
        wampproto::authenticators::anonymous::AnonymousAuthenticator,
    };

    tokio::time::timeout(Duration::from_secs(10), async {
        let router = Router::new();
        router.add_realm("example", RealmConfig::default()).unwrap();
        // Only the first authenticated connection is the backend in this local
        // fixture. Production policy uses authenticated roles or identities.
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let source_id = Arc::new(std::sync::atomic::AtomicI64::new(0));
        let observed = source_id.clone();
        router
            .route_streams(StreamRouting::new(
                move |_| first.swap(false, Ordering::SeqCst).then(|| "backend".into()),
                move |mut incoming| {
                    observed.store(incoming.session.id, Ordering::SeqCst);
                    async move {
                        let destination = incoming.stream.read_u8().await.map_err(|e| Error::new(e.to_string()))?;
                        Ok(incoming
                            .route_to(if destination == 1 { "backend" } else { "missing" })
                            .with_prefix(b"header".to_vec())
                            .with_failure(b"unavailable".to_vec()))
                    }
                },
                Arc::new(|source, _, target| source.realm == target.realm),
            ))
            .unwrap();
        let listener = Listener::bind(router.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let backend = Connection::connect(listener.local_addr, "localhost", listener.client_config().unwrap())
            .await
            .unwrap();
        let backend_session = backend
            .open_session(
                "example",
                Box::new(JSONSerializerSpec),
                Box::new(AnonymousAuthenticator::default()),
            )
            .await
            .unwrap();
        let client = Connection::connect(listener.local_addr, "localhost", listener.client_config().unwrap())
            .await
            .unwrap();
        let session = client
            .open_session(
                "example",
                Box::new(JSONSerializerSpec),
                Box::new(AnonymousAuthenticator::default()),
            )
            .await
            .unwrap();
        let mut request = client.open_raw().await.unwrap();
        request.write_all(&[1]).await.unwrap();
        request.write_all(b"body").await.unwrap();
        request.shutdown().await.unwrap();
        let mut incoming = backend.accept_raw().await.unwrap();
        let mut body = Vec::new();
        incoming.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"headerbody");
        incoming.write_all(b"reply").await.unwrap();
        incoming.shutdown().await.unwrap();
        let mut reply = Vec::new();
        request.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"reply");
        assert_eq!(source_id.load(Ordering::SeqCst), session.details().id());

        let mut missing = client.open_raw().await.unwrap();
        missing.write_all(&[0]).await.unwrap();
        missing.shutdown().await.unwrap();
        let mut failure = Vec::new();
        missing.read_to_end(&mut failure).await.unwrap();
        assert_eq!(failure, b"unavailable");
        session.close().await.unwrap();
        backend_session.close().await.unwrap();
        client.close();
        backend.close();
        listener.close();
        router.close();
    })
    .await
    .unwrap();
}
