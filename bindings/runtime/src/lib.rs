//! Foreign-language ownership and scheduling. Networking and WAMP stay in xconn.
mod callbacks;
mod client;
mod crypto;
mod jobs;
pub mod protocol;
#[cfg(feature = "quic")]
mod quic;
mod resources;
mod router;
mod services;
#[cfg(feature = "quic")]
mod stream_broker;
#[cfg(feature = "quic")]
mod tls;
mod values;
#[cfg(feature = "webtransport")]
mod webtransport;

#[cfg(feature = "webrtc")]
mod webrtc;
pub use jobs::{cancel, execute, ready, submit, submit_with_completion, take};
pub use resources::close;
use std::collections::HashMap;
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use values::{handle_field, string_field};
pub use xconn_core::{Value, wampproto::messages::types::ByteArray};

pub type Result<T> = std::result::Result<T, String>;

pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("binding runtime")
    })
}

fn id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

async fn dispatch(request_value: Value) -> Result<resources::Output> {
    let f = values::dictionary(&request_value)?;
    let timeout = values::duration_field(&f, "operation_timeout", None)?;
    match timeout.filter(|duration| !duration.is_zero()) {
        Some(timeout) => tokio::time::timeout(timeout, dispatch_fields(f))
            .await
            .map_err(|_| "operation timed out".to_string())?,
        None => dispatch_fields(f).await,
    }
}

async fn dispatch_fields(f: HashMap<String, Value>) -> Result<resources::Output> {
    let method = values::string_field(&f, "method")?;

    #[cfg(feature = "webrtc")]
    if method.starts_with("webrtc_") {
        return webrtc::dispatch(&method, f).await;
    }

    #[cfg(feature = "webtransport")]
    if method.starts_with("webtransport_") {
        return webtransport::dispatch(&method, f).await;
    }
    #[cfg(feature = "quic")]
    if method.starts_with("quic_") {
        return quic::dispatch(&method, f).await;
    }

    #[cfg(feature = "quic")]
    if method.starts_with("service_stream_") {
        return stream_broker::dispatch(&method, f).await;
    }
    if method.starts_with("service_") {
        return services::dispatch(&method, f).await;
    }

    let plain = |value| Ok(resources::Output::plain(value));

    match method.as_str() {
        "protocol" => {
            let input = match f.get("input") {
                Some(Value::Bytes(bytes)) => &bytes.0,
                _ => return Err("expected protocol input bytes".into()),
            };
            let operation = u32::try_from(handle_field(&f, "operation")?).map_err(|_| "invalid operation")?;
            let serializer = u32::try_from(handle_field(&f, "codec")?).map_err(|_| "invalid codec")?;
            plain(Value::Bytes(ByteArray(protocol::dispatch(
                operation, serializer, input,
            )?)))
        }
        "protocol_call" => {
            let args = f.get("args").cloned().unwrap_or(Value::List(vec![]));
            plain(protocol::call(Value::List(vec![
                Value::Str(string_field(&f, "name")?),
                args,
            ]))?)
        }
        "close" => {
            close(handle_field(&f, "handle")?);
            plain(Value::Null)
        }
        "callbacks_new" | "callbacks_next" | "callbacks_reply" => callbacks::dispatch(&method, f).await,
        "listen"
        | "permission_match"
        | "protocol_select"
        | "realm_add"
        | "realm_alias"
        | "realm_authorizer"
        | "realm_has"
        | "realm_meta"
        | "realm_remove"
        | "role_add"
        | "role_has"
        | "role_remove"
        | "router_detach"
        | "router_new"
        | "router_stop"
        | "websocket_protocols" => router::dispatch(&method, f).await,
        _ => client::dispatch(&method, f).await,
    }
}
