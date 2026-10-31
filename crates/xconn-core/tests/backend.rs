#![cfg(feature = "services")]
use std::time::Duration;
use xconn_core::{
    Error, Result as RpcResult, Value,
    async_::{
        client::{Client, connect_anonymous},
        router::{RealmConfig, Router},
        server::Server,
    },
};

#[tokio::test]
async fn backend_restores_registrations_after_reconnect_and_closes_on_cancel() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let router = Router::new();
        router.add_realm("example", RealmConfig::default()).unwrap();
        let server = Server::websocket(router.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let uri = format!("ws://{}", server.local_addr);
        let (ready, mut observed) = tokio::sync::mpsc::channel(3);
        let target = uri.clone();
        let backend = tokio::spawn(async move {
            Client::default()
                .serve(&target, "example", |session| {
                    let ready = ready.clone();
                    async move {
                        let registered = session
                            .register("example.echo", |invocation| async move {
                                RpcResult::new(invocation.args, invocation.kwargs)
                            })
                            .execute()
                            .await?;
                        assert!(registered.error.is_none());
                        ready.send(session).await.unwrap();
                        Ok(())
                    }
                })
                .await
        });
        let mut caller = connect_anonymous(&uri, "example").await.unwrap();
        let mut serving = observed.recv().await.unwrap();
        for _ in 0..2 {
            assert_eq!(
                caller.call("example.echo").arg(7).execute().await.unwrap().args,
                Some(vec![Value::Int(7)])
            );
            router.close();
            caller.wait_disconnect().await;
            router.add_realm("example", RealmConfig::default()).unwrap();
            caller = connect_anonymous(&uri, "example").await.unwrap();
            serving = observed.recv().await.unwrap();
        }
        backend.abort();
        assert!(backend.await.unwrap_err().is_cancelled());
        serving.wait_disconnect().await;
        caller.close().await.unwrap();
        server.close();
        router.close();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn setup_errors_stop_the_backend_instead_of_retrying() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let router = Router::new();
        router.add_realm("example", RealmConfig::default()).unwrap();
        let server = Server::websocket(router.clone(), "127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let uri = format!("ws://{}", server.local_addr);
        let error = Client::default()
            .serve(&uri, "example", |_| async { Err(Error::new("invalid service setup")) })
            .await
            .unwrap_err();
        assert_eq!(error.message, "invalid service setup");
        server.close();
        router.close();
    })
    .await
    .unwrap();
}
