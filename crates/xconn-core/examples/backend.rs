//! A backend using normal WAMP APIs; reconnection and cleanup are runtime work.
use xconn_core::{
    Result as RpcResult,
    async_::{
        client::{Client, connect_anonymous},
        router::{RealmConfig, Router},
        server::Server,
    },
};

const REALM: &str = "example";
const PROCEDURE: &str = "example.echo";
const URI: &str = "ws://127.0.0.1:8080";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("hub") => {
            let router = Router::new();
            router.add_realm(REALM, RealmConfig::default())?;
            let server = Server::websocket(router.clone(), "127.0.0.1:8080".parse()?).await?;
            println!("{URI}, realm {REALM}");
            tokio::signal::ctrl_c().await?;
            server.close();
            router.close();
        }
        Some("backend") => {
            let client = Client::default();
            tokio::select! {
                result = client.serve(URI, REALM, |session| async move {
                    let registered = session.register(PROCEDURE, |invocation| async move {
                        RpcResult::new(invocation.args, invocation.kwargs)
                    }).execute().await?;
                    if let Some(error) = registered.error {
                        return Err(xconn_core::Error::application(error));
                    }
                    Ok(())
                }) => result?,
                result = tokio::signal::ctrl_c() => result?,
            }
        }
        Some("call") => {
            let session = connect_anonymous(URI, REALM).await?;
            let result = session.call(PROCEDURE).arg("hello").execute().await?;
            session.close().await?;
            if let Some(error) = result.error {
                return Err(xconn_core::Error::application(error).into());
            }
            println!("{:?}", result.args);
        }
        _ => return Err("usage: backend hub|backend|call".into()),
    }
    Ok(())
}
