//! RPC forwarding without application-specific identity or authorization policy.
use crate::async_::{
    call::Call,
    session::{InvocationContext, Session, Subscription},
    types::SubscribeRequest,
};
use crate::wampproto::messages::schema::WireValue;
use crate::{CallRequest, Error, RpcResult, StreamOptions, Value, WampError};
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};
use tokio::sync::{Mutex, watch};

/// The application chooses how a disclosed caller obtains a backend session.
/// Sessions returned by this factory are owned by the bridge.
pub type SessionFactory =
    Arc<dyn Fn(Caller) -> Pin<Box<dyn Future<Output = Result<Session, Error>> + Send>> + Send + Sync>;

#[derive(Clone, Debug)]
pub struct Caller {
    pub session_id: i64,
    pub authid: String,
    pub authrole: String,
}

#[derive(Clone, Debug)]
pub struct BridgeRoute {
    pub procedure: String,
    pub options: HashMap<String, Value>,
}

impl BridgeRoute {
    pub fn exact(procedure: impl Into<String>) -> Self {
        Self {
            procedure: procedure.into(),
            options: HashMap::new(),
        }
    }

    pub fn prefix(prefix: impl Into<String>) -> Self {
        Self {
            procedure: prefix.into(),
            options: HashMap::from([("match".into(), Value::Str("prefix".into()))]),
        }
    }
}

struct Callers {
    closed: bool,
    sessions: HashMap<i64, Session>,
}

type ForwardedCalls = Arc<Mutex<HashMap<i64, Arc<Call>>>>;

struct ForwardingGuard {
    context: InvocationContext,
    id: i64,
    call: Arc<Call>,
    calls: ForwardedCalls,
}

impl Drop for ForwardingGuard {
    fn drop(&mut self) {
        if !self.call.is_finished() {
            self.call.cancel();
        }
        let (id, call, calls) = (self.id, self.call.clone(), self.calls.clone());
        let context = self.context.clone();
        tokio::spawn(async move {
            // A backend may finish before the caller's final input. Retain its
            // completed call until the source invocation sends its final reply
            // or is interrupted, so already-queued chunks cannot reopen it.
            context.cancelled().await;
            let mut calls = calls.lock().await;
            if calls.get(&id).is_some_and(|current| Arc::ptr_eq(current, &call)) {
                calls.remove(&id);
            }
        });
    }
}

struct Forwarder {
    calls: ForwardedCalls,
    target: Session,
    factory: Option<SessionFactory>,
    callers: Mutex<Callers>,
    stopped: watch::Sender<bool>,
}

impl Forwarder {
    async fn target(&self, context: &InvocationContext) -> Result<Session, Error> {
        let mut callers = self.callers.lock().await;
        if callers.closed {
            return Err(Error::new("bridge closed"));
        }
        let Some(factory) = &self.factory else {
            return Ok(self.target.clone());
        };
        let fields = &context.invocation.details;
        let session_id = fields
            .get("caller")
            .and_then(Value::integer)
            .filter(|id| *id > 0)
            .ok_or_else(|| Error::new("caller disclosure is required"))?;
        if let Some(session) = callers.sessions.get(&session_id) {
            return Ok(session.clone());
        }
        let text = |key: &str| match fields.get(key) {
            Some(Value::Str(value)) => value.clone(),
            _ => String::new(),
        };
        let session = factory(Caller {
            session_id,
            authid: text("caller_authid"),
            authrole: text("caller_authrole"),
        })
        .await?;
        callers.sessions.insert(session_id, session.clone());
        Ok(session)
    }

    async fn forward(&self, context: InvocationContext, procedure: String, prefix: bool) -> RpcResult {
        let mut stopped = self.stopped.subscribe();
        tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => RpcResult::error("wamp.error.canceled"),
            _ = context.cancelled() => RpcResult::error("wamp.error.canceled"),
            result = self.forward_call(&context, procedure, prefix) => result,
        }
    }

    async fn forward_call(&self, context: &InvocationContext, procedure: String, prefix: bool) -> RpcResult {
        let more = context.invocation.details.get("progress") == Some(&Value::Bool(true));
        let mut calls = self.calls.lock().await;
        if let Some(call) = calls.get(&context.request_id).cloned() {
            drop(calls);
            let args = context.payload_args().clone().unwrap_or_default();
            let kwargs = context.payload_kwargs().clone().unwrap_or_default();
            let result = if more {
                call.send(args, kwargs).await
            } else {
                call.finish(args, kwargs).await
            };
            if result.is_err() && !call.is_finished() {
                call.cancel();
            }
            // The first handler owns the result path and sends the terminal reply.
            return RpcResult::no_result();
        }
        let target = match self.target(context).await {
            Ok(target) => target,
            Err(error) => return failure(error),
        };
        let procedure = if prefix {
            match context.invocation.details.get("procedure") {
                Some(Value::Str(procedure)) => procedure.clone(),
                _ => return RpcResult::error("wamp.error.invalid_argument"),
            }
        } else {
            procedure
        };
        let mut request = CallRequest::new(procedure);
        if let Some(args) = context.payload_args() {
            request = request.args(args.clone());
        }
        if let Some(kwargs) = context.payload_kwargs() {
            request = request.kwargs(kwargs.clone());
        }
        let options = StreamOptions {
            progressive_input: more,
            progressive_results: context.invocation.details.get("receive_progress") == Some(&Value::Bool(true)),
            ..Default::default()
        };
        let call = match Call::open(&target, request, options).await {
            Ok(call) => call,
            Err(error) => return failure(error),
        };
        let call = Arc::new(call);
        calls.insert(context.request_id, call.clone());
        drop(calls);
        let _guard = ForwardingGuard {
            context: context.clone(),
            id: context.request_id,
            call: call.clone(),
            calls: self.calls.clone(),
        };
        self.receive_results(context, &call).await
    }

    async fn receive_results(&self, context: &InvocationContext, call: &Call) -> RpcResult {
        let mut stopped = self.stopped.subscribe();
        let results = async {
            loop {
                match call.receive().await {
                    Ok(Some(result)) if result.details.get("progress") == Some(&Value::Bool(true)) => {
                        if let Err(error) = context.send_progress_payload(result.args, result.kwargs).await {
                            return failure(error);
                        }
                    }
                    Ok(Some(result)) => return result,
                    Ok(None) => return RpcResult::error("wamp.error.canceled"),
                    Err(error) => return failure(error),
                }
            }
        };
        let result = tokio::select! {
            biased;
            _ = stopped.wait_for(|stopped| *stopped) => RpcResult::error("wamp.error.canceled"),
            _ = context.cancelled() => RpcResult::error("wamp.error.canceled"),
            result = results => result,
        };
        if !call.is_finished() {
            call.cancel();
        }
        result
    }
}

struct Inner {
    source: Session,
    forwarder: Arc<Forwarder>,
    registrations: Mutex<Vec<i64>>,
    subscription: Mutex<Option<Subscription>>,
    close_gate: Mutex<()>,
}

impl Inner {
    async fn close(&self) -> Result<(), Error> {
        let _gate = self.close_gate.lock().await;
        self.forwarder.stopped.send_replace(true);
        for call in self.forwarder.calls.lock().await.drain().map(|(_, call)| call) {
            call.cancel();
        }
        let sessions = {
            let mut callers = self.forwarder.callers.lock().await;
            callers.closed = true;
            std::mem::take(&mut callers.sessions)
        };
        for session in sessions.into_values() {
            let _ = session.close().await;
        }
        let registrations = std::mem::take(&mut *self.registrations.lock().await);
        let subscription = self.subscription.lock().await.take();
        // The router already removed these resources when the source left.
        if !self.source.connected() {
            return Ok(());
        }
        let mut failure = None;
        for id in registrations {
            if let Err(error) = self.source.unregister(id).await {
                failure.get_or_insert(error);
            }
        }
        if let Some(subscription) = subscription
            && let Err(error) = subscription.unsubscribe().await
        {
            failure.get_or_insert(error);
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

/// Owns forwarding registrations and any per-caller backend sessions.
/// Source and shared target sessions remain owned by their callers.
pub struct Bridge {
    inner: Arc<Inner>,
    executor: tokio::runtime::Handle,
}

impl Bridge {
    pub async fn new(
        source: Session,
        target: Session,
        routes: Vec<BridgeRoute>,
        factory: Option<SessionFactory>,
    ) -> Result<Self, Error> {
        let stopped = watch::channel(false).0;
        let forwarder = Arc::new(Forwarder {
            calls: Arc::new(Mutex::new(HashMap::new())),
            target,
            factory,
            callers: Mutex::new(Callers {
                closed: false,
                sessions: HashMap::new(),
            }),
            stopped,
        });
        let bridge = Self {
            inner: Arc::new(Inner {
                source: source.clone(),
                forwarder: forwarder.clone(),
                registrations: Mutex::new(Vec::new()),
                subscription: Mutex::new(None),
                close_gate: Mutex::new(()),
            }),
            executor: tokio::runtime::Handle::current(),
        };
        if forwarder.factory.is_some() {
            let callers = forwarder.clone();
            let subscription = source
                .subscribe_handle(SubscribeRequest::new("wamp.session.on_leave", move |event| {
                    let callers = callers.clone();
                    async move {
                        let Some(id) = event.args.first().and_then(Value::integer) else {
                            return;
                        };
                        let session = callers.callers.lock().await.sessions.remove(&id);
                        if let Some(session) = session {
                            let _ = session.close().await;
                        }
                    }
                }))
                .await?;
            *bridge.inner.subscription.lock().await = Some(subscription);
        }
        for route in routes {
            let prefix = matches!(route.options.get("match"), Some(Value::Str(policy)) if policy == "prefix");
            let procedure = route.procedure.clone();
            let forwarder = forwarder.clone();
            let response = source
                .register_context(route.procedure, route.options, move |context| {
                    let forwarder = forwarder.clone();
                    let procedure = procedure.clone();
                    async move { forwarder.forward(context, procedure, prefix).await }
                })
                .await?;
            if let Some(error) = response.error {
                return Err(Error::application(error));
            }
            bridge.inner.registrations.lock().await.push(response.registration_id);
        }
        let inner = Arc::downgrade(&bridge.inner);
        let mut stopped = forwarder.stopped.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                _ = stopped.wait_for(|stopped| *stopped) => return,
                _ = source.wait_disconnect() => {},
            }
            if let Some(inner) = inner.upgrade() {
                let _ = inner.close().await;
            }
        });
        Ok(bridge)
    }

    pub async fn close(&self) -> Result<(), Error> {
        self.inner.close().await
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.inner.forwarder.stopped.send_replace(true);
        let inner = self.inner.clone();
        self.executor.spawn(async move {
            let _ = inner.close().await;
        });
    }
}

fn failure(error: Error) -> RpcResult {
    RpcResult {
        error: Some(error.application.unwrap_or_else(|| WampError {
            uri: "wamp.error.operation_failed".into(),
            args: Some(vec![Value::Str(error.message)]),
            ..Default::default()
        })),
        ..Default::default()
    }
}
