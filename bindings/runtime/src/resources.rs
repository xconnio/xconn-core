//! Resource handles, transfer ownership and compensating cleanup.
#[cfg(feature = "webrtc")]
use crate::webrtc;
use crate::{
    Result, Value,
    callbacks::ForeignCallbacks,
    id, runtime,
    values::{duration_field, object_value},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, atomic::Ordering},
};
use tokio::sync::{mpsc, oneshot};
use xconn_core::{
    Result as RpcResult,
    async_::{
        router::Router,
        server::Server,
        session::{Session, Subscription},
    },
};

fn resources() -> &'static Mutex<HashMap<u64, Arc<Resource>>> {
    static MAP: OnceLock<Mutex<HashMap<u64, Arc<Resource>>>> = OnceLock::new();
    MAP.get_or_init(Default::default)
}

pub(super) struct ForeignBase {
    pub(super) peer: Arc<dyn xconn_core::async_::peer::Peer>,
    pub(super) details: xconn_core::SessionDetails,
    pub(super) serializer: Box<dyn xconn_core::wampproto::serializers::serializer::Serializer>,
    pub(super) transferred: std::sync::atomic::AtomicBool,
}

pub(super) fn get_base(handle: u64) -> Result<Arc<ForeignBase>> {
    match get_resource(handle)?.as_ref() {
        Resource::Base(base) => Ok(base.clone()),
        _ => Err("expected base session".into()),
    }
}

pub(super) enum Resource {
    #[cfg(feature = "quic")]
    StreamBroker(xconn_core::async_::services::stream_broker::StreamBroker),
    #[cfg(feature = "quic")]
    StreamDestination(xconn_core::async_::services::stream_broker::DestinationRegistration),
    Discovery(Arc<xconn_core::async_::services::discovery::DiscoveryService>),
    Bridge(Arc<xconn_core::async_::services::bridge::Bridge>),
    #[cfg(feature = "quic")]
    Quic(crate::quic::Resource),
    #[cfg(feature = "webtransport")]
    WebTransport(crate::webtransport::Resource),
    #[cfg(feature = "webrtc")]
    WebRTC(webrtc::Resource),
    Router {
        router: Router,
        _management: Option<Box<xconn_core::async_::management::Management>>,
    },
    Session(Arc<ForeignSession>),
    Listener(Server),
    #[cfg(unix)]
    UnixListener(xconn_core::async_::server::UnixServer),
    Callbacks(Arc<ForeignCallbacks>),
    Call(Arc<ForeignCall>),
    Stream(xconn_core::async_::call::Call),
    Base(Arc<ForeignBase>),
}

impl Resource {
    pub(super) fn close(&self) {
        match self {
            #[cfg(feature = "quic")]
            Self::StreamBroker(_) => {}
            #[cfg(feature = "quic")]
            Self::StreamDestination(registration) => registration.close(),
            Self::Discovery(service) => {
                let service = service.clone();
                runtime().spawn(async move {
                    let _ = service.close().await;
                });
            }
            Self::Bridge(bridge) => {
                let bridge = bridge.clone();
                runtime().spawn(async move {
                    let _ = bridge.close().await;
                });
            }
            #[cfg(feature = "quic")]
            Self::Quic(resource) => resource.close(),
            #[cfg(feature = "webtransport")]
            Self::WebTransport(resource) => resource.close(),
            #[cfg(feature = "webrtc")]
            Self::WebRTC(resource) => resource.close(),
            Self::Router { router, .. } => router.close(),
            Self::Session(s) => {
                if let Some(heartbeat) = s.heartbeat.lock().unwrap().take() {
                    heartbeat.abort();
                }

                let s = s.clone();
                runtime().spawn(async move {
                    let _ = s.session.close().await;
                });
            }
            Self::Listener(l) => l.close(),
            #[cfg(unix)]
            Self::UnixListener(listener) => listener.close(),
            Self::Callbacks(callbacks) => callbacks.close(),
            Self::Call(call) => call.task.abort(),
            Self::Stream(call) => call.cancel(),
            Self::Base(base) => {
                if !base.transferred.load(Ordering::Acquire) {
                    let peer = base.peer.clone();
                    runtime().spawn(async move {
                        let _ = peer.close().await;
                    });
                }
            }
        }
    }
}

impl Drop for Resource {
    fn drop(&mut self) {
        self.close();
    }
}

pub fn close(handle: u64) {
    if let Some(resource) = resources().lock().unwrap().remove(&handle) {
        resource.close();
    }
}

#[cfg(feature = "quic")]
pub(super) fn take_resource(handle: u64) -> Result<Arc<Resource>> {
    resources()
        .lock()
        .unwrap()
        .remove(&handle)
        .ok_or("closed or invalid resource".into())
}

pub(super) fn get_resource(handle: u64) -> Result<Arc<Resource>> {
    resources()
        .lock()
        .unwrap()
        .get(&handle)
        .cloned()
        .ok_or("closed or invalid resource".into())
}

pub(super) fn get_session(handle: u64) -> Result<Arc<ForeignSession>> {
    match get_resource(handle)?.as_ref() {
        Resource::Session(s) => Ok(s.clone()),
        _ => Err("expected session".into()),
    }
}

pub(super) fn get_router(handle: u64) -> Result<Router> {
    match get_resource(handle)?.as_ref() {
        Resource::Router { router, .. } => Ok(router.clone()),
        _ => Err("expected router".into()),
    }
}

pub(super) struct ForeignSession {
    heartbeat: Mutex<Option<tokio::task::AbortHandle>>,
    pub(super) session: Session,
    pub(super) events: mpsc::Sender<Value>,
    pub(super) receiver: tokio::sync::Mutex<mpsc::Receiver<Value>>,
    pub(super) invocations: Mutex<HashMap<u64, oneshot::Sender<RpcResult>>>,
    pub(super) invocation_contexts: Mutex<HashMap<u64, xconn_core::async_::session::InvocationContext>>,
    pub(super) subscriptions: Mutex<HashMap<u64, Arc<Subscription>>>,
}

impl ForeignSession {
    pub(super) fn new(session: Session) -> Self {
        let (events, receiver) = mpsc::channel(256);
        Self {
            heartbeat: Mutex::new(None),
            session,
            events,
            receiver: tokio::sync::Mutex::new(receiver),
            invocations: Mutex::new(HashMap::new()),
            invocation_contexts: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(HashMap::new()),
        }
    }
}

impl ForeignSession {
    pub(super) fn keep_alive(self: &Arc<Self>, fields: &HashMap<String, Value>) -> Result<()> {
        let Some(interval) = duration_field(fields, "ping_interval", None)? else {
            return Ok(());
        };
        let timeout = duration_field(fields, "ping_timeout", Some(std::time::Duration::from_secs(10)))?;
        let weak = Arc::downgrade(self);
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let Some(session) = weak.upgrade() else {
                    return;
                };

                if !session.session.connected() {
                    return;
                }

                if session.session.ping_with_timeout(timeout).await.is_err() {
                    let _ = session.session.close().await;
                    return;
                }
            }
        });
        *self.heartbeat.lock().unwrap() = Some(task.abort_handle());
        Ok(())
    }
}

pub(super) enum Cleanup {
    #[cfg(feature = "webrtc")]
    Handles(Vec<u64>),
    Handle(u64),
    Registration(Arc<ForeignSession>, i64),
    Subscription(Arc<ForeignSession>, u64),
}

pub(super) struct Output {
    pub(super) value: Value,
    pub(super) owned: Option<Cleanup>,
}

impl Output {
    pub(super) fn plain(value: Value) -> Self {
        Self { value, owned: None }
    }

    pub(super) fn resource(resource: Resource, mut fields: HashMap<String, Value>) -> Self {
        let handle = id();
        resources().lock().unwrap().insert(handle, Arc::new(resource));
        fields.insert("handle".into(), Value::UInt(handle));
        Self {
            value: Value::Dict(fields),
            owned: Some(Cleanup::Handle(handle)),
        }
    }

    #[cfg(feature = "webrtc")]
    pub(super) fn with_resource(mut self, key: &str, resource: Resource) -> Self {
        let handle = id();
        resources().lock().unwrap().insert(handle, Arc::new(resource));

        if let Value::Dict(fields) = &mut self.value {
            fields.insert(key.into(), Value::UInt(handle));
        }

        let mut handles = match self.owned.take() {
            Some(Cleanup::Handle(handle)) => vec![handle],
            Some(Cleanup::Handles(handles)) => handles,
            None => Vec::new(),
            _ => unreachable!("only resource outputs can acquire resources"),
        };
        handles.push(handle);
        self.owned = Some(Cleanup::Handles(handles));
        self
    }

    pub(super) fn take(mut self) -> Value {
        self.owned = None;
        std::mem::replace(&mut self.value, Value::Null)
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if let Some(cleanup) = self.owned.take() {
            match cleanup {
                Cleanup::Handle(handle) => close(handle),
                #[cfg(feature = "webrtc")]
                Cleanup::Handles(handles) => {
                    for handle in handles {
                        close(handle);
                    }
                }
                Cleanup::Registration(s, id) => {
                    runtime().spawn(async move {
                        let _ = s.session.unregister(id).await;
                    });
                }
                Cleanup::Subscription(s, token) => {
                    let subscription = s.subscriptions.lock().unwrap().remove(&token);

                    if let Some(subscription) = subscription {
                        runtime().spawn(async move {
                            let _ = subscription.unsubscribe().await;
                        });
                    }
                }
            }
        }
    }
}

pub(super) struct CallInput {
    pub(super) args: Vec<Value>,
    pub(super) kwargs: HashMap<String, Value>,
    pub(super) more: bool,
    pub(super) reply: oneshot::Sender<Result<()>>,
}

pub(super) struct ForeignCall {
    pub(super) input: mpsc::Sender<CallInput>,
    pub(super) output: tokio::sync::Mutex<mpsc::Receiver<std::result::Result<RpcResult, xconn_core::Error>>>,
    pub(super) task: tokio::task::AbortHandle,
}

pub(super) fn get_call(handle: u64) -> Result<Arc<ForeignCall>> {
    match get_resource(handle)?.as_ref() {
        Resource::Call(call) => Ok(call.clone()),
        _ => Err("expected call stream".into()),
    }
}

pub(super) struct InvocationGuard {
    pub(super) session: Arc<ForeignSession>,
    pub(super) id: u64,
}

impl Drop for InvocationGuard {
    fn drop(&mut self) {
        self.session.invocation_contexts.lock().unwrap().remove(&self.id);

        if self.session.invocations.lock().unwrap().remove(&self.id).is_some() {
            let events = self.session.events.clone();
            let id = self.id;
            runtime().spawn(async move {
                let _ = events
                    .send(object_value([
                        ("kind", Value::Str("interrupt".into())),
                        ("id", Value::UInt(id)),
                    ]))
                    .await;
            });
        }
    }
}
