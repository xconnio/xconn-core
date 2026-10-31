//! Async realm runtime. WAMP routing and authentication are delegated to wampproto.
use super::{
    joiner::join,
    peer::{MemoryPeer, Peer},
    session::Session,
};
use crate::_SerializerSpec;
use crate::{CBORSerializerSpec, Error, JSONSerializerSpec, MsgPackSerializerSpec, SerializerSpec};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use wampproto::{
    acceptor::Acceptor,
    authenticators::server::{AnonymousAuthenticator, ServerAuthenticator},
    broker::Broker,
    dealer::Dealer,
    messages::{
        cancel::Cancel, error::Error as ProtocolError, goodbye::Goodbye, message::Message, publish::Publish,
        types::Value,
    },
    routing::{MatchPolicy, RoutedMessage},
    serializers::serializer::Serializer,
    types::SessionDetails,
};

pub type AuthenticationFactory = Arc<dyn Fn() -> Box<dyn ServerAuthenticator> + Send + Sync>;
pub type Authorizer = Arc<dyn Fn(&SessionDetails, &dyn Message) -> bool + Send + Sync>;

#[derive(Clone, Debug)]
pub struct Permission {
    pub uri: String,
    pub matching: MatchPolicy,
    pub call: bool,
    pub register: bool,
    pub publish: bool,
    pub subscribe: bool,
}

impl Permission {
    pub fn all() -> Self {
        Self {
            uri: String::new(),
            matching: MatchPolicy::Prefix,
            call: true,
            register: true,
            publish: true,
            subscribe: true,
        }
    }

    fn allows(&self, code: i64, uri: &str) -> bool {
        self.matching.matches(&self.uri, uri)
            && match code {
                16 => self.publish,
                32 => self.subscribe,
                48 => self.call,
                64 => self.register,
                _ => false,
            }
    }
}

#[derive(Clone)]
pub struct RealmConfig {
    pub authentication: AuthenticationFactory,
    pub roles: HashMap<String, Vec<Permission>>,
    pub authorizer: Option<Authorizer>,
    pub meta_api: bool,
    pub disclose_caller: bool,
    pub disclose_publisher: bool,
}

impl Default for RealmConfig {
    fn default() -> Self {
        Self {
            authentication: Arc::new(|| Box::new(AnonymousAuthenticator)),
            roles: HashMap::from([
                ("anonymous".into(), vec![Permission::all()]),
                ("trusted".into(), vec![Permission::all()]),
            ]),
            authorizer: None,
            meta_api: false,
            disclose_caller: false,
            disclose_publisher: false,
        }
    }
}

struct Client {
    attachment: Arc<()>,
    details: SessionDetails,
    serializer: Box<dyn Serializer>,
    outgoing: mpsc::Sender<Vec<u8>>,
}

struct Realm {
    config: RealmConfig,
    broker: Broker,
    dealer: Dealer,
    clients: HashMap<i64, Client>,
}

impl Realm {
    fn new(config: RealmConfig) -> Self {
        let mut broker = Broker::new();
        broker.auto_disclose_publisher(config.disclose_publisher);
        let mut dealer = Dealer::new();
        dealer.auto_disclose_caller(config.disclose_caller);
        Self {
            config,
            broker,
            dealer,
            clients: HashMap::new(),
        }
    }

    fn deliver(&self, recipient: i64, message: &dyn Message) -> Result<(), Error> {
        if let Some(client) = self.clients.get(&recipient) {
            let data = client.serializer.serialize(message)?;
            client
                .outgoing
                .try_send(data)
                .map_err(|_| Error::new("recipient unavailable or queue full"))?;
        }

        Ok(())
    }

    fn routed(&self, messages: Vec<RoutedMessage>) {
        for routed in messages {
            let _ = self.deliver(routed.recipient, routed.message.as_ref());
        }
    }

    fn detach(&mut self, id: i64) {
        if self.config.meta_api && self.clients.contains_key(&id) {
            self.meta_event(id, false);
        }

        if self.clients.remove(&id).is_none() {
            return;
        }

        let _ = self.broker.remove_session(id);

        if let Ok(messages) = self.dealer.remove_session(id) {
            self.routed(messages);
        }
    }

    fn dispatch(&mut self, id: i64, msg: &dyn Message, dynamic_authorized: bool) -> Result<bool, Error> {
        let code = match msg.message_type() {
            Value::Int(v) => v,
            _ => return Err(Error::new("invalid message type")),
        };

        if matches!(code, 16 | 32 | 48 | 64) {
            let fields = wampproto::messages::schema::schema(code)
                .unwrap()
                .parse(&Value::List(msg.marshal()))
                .map_err(|e| Error::new(e.join("; ")))?;
            let uri = match fields.get(if matches!(code, 48 | 64) { "procedure" } else { "topic" }) {
                Some(Value::Str(v)) => v,
                _ => return Err(Error::new("missing URI")),
            };
            let client = self.clients.get(&id).ok_or_else(|| Error::new("unknown session"))?;
            let allowed = self
                .config
                .roles
                .get(&client.details.auth_role)
                .is_some_and(|rules| rules.iter().any(|p| p.allows(code, uri)))
                || dynamic_authorized;
            if !allowed {
                let ack = code != 16
                    || msg
                        .as_any()
                        .downcast_ref::<Publish>()
                        .is_some_and(|p| p.options.get("acknowledge") == Some(&Value::Bool(true)));
                if ack {
                    let request_id = match fields.get("request_id") {
                        Some(Value::Int(v)) => *v,
                        _ => return Err(Error::new("missing request ID")),
                    };
                    self.deliver(
                        id,
                        &ProtocolError {
                            message_type: Value::Int(code),
                            request_id,
                            options: HashMap::new(),
                            uri: "wamp.error.authorization_failed".into(),
                            args: None,
                            kwargs: None,
                        },
                    )?;
                }

                return Ok(true);
            }
        }

        if self.config.meta_api && code == 48 {
            let call = msg.as_any().downcast_ref::<wampproto::messages::call::Call>().unwrap();

            if self.meta_call(id, call)? {
                return Ok(true);
            }
        }

        match code {
            6 => {
                self.deliver(
                    id,
                    &Goodbye {
                        details: HashMap::new(),
                        reason: "wamp.close.goodbye_and_out".into(),
                    },
                )?;
                Ok(false)
            }
            16 => {
                let publication = self.broker.receive_publish(
                    id,
                    msg.as_any()
                        .downcast_ref::<Publish>()
                        .ok_or_else(|| Error::new("invalid PUBLISH"))?,
                )?;

                for delivery in publication.events {
                    for recipient in delivery.recipients {
                        let _ = self.deliver(recipient, delivery.event.as_ref());
                    }
                }

                if let Some(ack) = publication.ack {
                    self.deliver(ack.recipient, ack.message.as_ref())?;
                }

                Ok(true)
            }
            32 | 34 => {
                let routed = self.broker.receive_message(id, msg)?;
                self.deliver(routed.recipient, routed.message.as_ref())?;
                Ok(true)
            }
            49 => {
                let out = self.dealer.receive_cancel(
                    id,
                    msg.as_any()
                        .downcast_ref::<Cancel>()
                        .ok_or_else(|| Error::new("invalid CANCEL"))?,
                )?;
                self.routed(out);
                Ok(true)
            }
            8 | 48 | 64 | 66 | 70 => {
                if let Some(out) = self.dealer.receive_message(id, msg)?
                    && let Err(err) = self.deliver(out.recipient, out.message.as_ref())
                {
                    // Remove a blocked callee so pending calls receive disconnect errors.
                    self.detach(out.recipient);

                    if out.recipient == id {
                        return Err(err);
                    }
                }

                Ok(true)
            }
            _ => Err(Error::new("unexpected router message")),
        }
    }
}

#[derive(Clone, Default)]
pub struct Router {
    #[cfg(all(feature = "services", any(feature = "quic", feature = "webtransport")))]
    stream_routing: Arc<Mutex<Option<super::services::routing::StreamRouting>>>,
    keepalive: Option<(Duration, Duration)>,
    authentication_override: Option<AuthenticationFactory>,
    realms: Arc<Mutex<HashMap<String, Arc<Mutex<Realm>>>>>,
}

impl Router {
    pub fn with_authentication(mut self, authentication: AuthenticationFactory) -> Self {
        self.authentication_override = Some(authentication);
        self
    }

    /// Probe established peers and close connections that fail to answer.
    pub fn with_keepalive(mut self, interval: Duration, timeout: Duration) -> Result<Self, Error> {
        if interval.is_zero() || timeout.is_zero() {
            return Err(Error::new("keepalive interval and timeout must be positive"));
        }
        self.keepalive = Some((interval, timeout));
        Ok(self)
    }

    /// Configure stream routing before binding listeners. Ordinary WAMP routing
    /// is unchanged. An authenticated connection's identity selects destinations.
    #[cfg(all(feature = "services", any(feature = "quic", feature = "webtransport")))]
    pub fn route_streams(&self, routing: super::services::routing::StreamRouting) -> Result<(), Error> {
        let mut current = self.stream_routing.lock().unwrap();
        if current.is_some() {
            return Err(Error::new("stream routing is already configured"));
        }
        *current = Some(routing);
        Ok(())
    }

    #[cfg(all(feature = "services", any(feature = "quic", feature = "webtransport")))]
    pub(crate) fn stream_routing(&self) -> Option<super::services::routing::StreamRouting> {
        self.stream_routing.lock().unwrap().clone()
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_realm(&self, name: impl Into<String>, config: RealmConfig) -> Result<(), Error> {
        let mut realms = self.realms.lock().unwrap();
        let name = name.into();

        if realms.contains_key(&name) {
            return Err(Error::new("realm already exists"));
        }

        realms.insert(name, Arc::new(Mutex::new(Realm::new(config))));
        Ok(())
    }

    pub fn has_realm(&self, name: &str) -> bool {
        self.realms.lock().unwrap().contains_key(name)
    }

    pub fn add_alias(&self, name: &str, alias: impl Into<String>) -> Result<(), Error> {
        let mut realms = self.realms.lock().unwrap();
        let realm = realms.get(name).cloned().ok_or_else(|| Error::new("no such realm"))?;
        let alias = alias.into();

        if realms.contains_key(&alias) {
            return Err(Error::new("realm already exists"));
        }

        realms.insert(alias, realm);
        Ok(())
    }

    pub fn sessions(&self, name: &str) -> Result<Vec<SessionDetails>, Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        let result = realm
            .lock()
            .unwrap()
            .clients
            .values()
            .map(|c| c.details.clone())
            .collect();
        Ok(result)
    }

    pub async fn connect(
        &self,
        realm: &str,
        spec: Box<dyn SerializerSpec>,
        auth: Box<dyn wampproto::authenticators::authenticator::ClientAuthenticator + Send + Sync>,
    ) -> Result<Session, Error> {
        let (client, server) = MemoryPeer::pair(256);
        let router = self.clone();
        let serializer = spec.serializer();
        tokio::spawn(async move {
            let _ = router.accept(server, serializer).await;
        });
        let serializer = spec.serializer();
        let (peer, details) =
            tokio::time::timeout(Duration::from_secs(10), join(client, realm, spec.serializer(), auth))
                .await
                .map_err(|_| Error::new("handshake timeout"))??;
        Ok(Session::new(details, peer, serializer))
    }

    pub async fn accept(&self, peer: Box<dyn Peer>, serializer: Box<dyn Serializer>) -> Result<(), Error> {
        let peer: Arc<dyn Peer> = Arc::from(peer);
        let result = self.serve(peer.clone(), serializer, None).await;
        let _ = peer.close().await;
        result
    }

    pub async fn accept_notified(
        &self,
        peer: Box<dyn Peer>,
        serializer: Box<dyn Serializer>,
        authenticated: tokio::sync::watch::Sender<Option<SessionDetails>>,
    ) -> Result<(), Error> {
        let peer: Arc<dyn Peer> = Arc::from(peer);
        let result = self.serve(peer.clone(), serializer, Some(authenticated)).await;
        let _ = peer.close().await;
        result
    }

    async fn serve(
        &self,
        peer: Arc<dyn Peer>,
        serializer: Box<dyn Serializer>,
        authenticated: Option<tokio::sync::watch::Sender<Option<SessionDetails>>>,
    ) -> Result<(), Error> {
        let hello = tokio::time::timeout(Duration::from_secs(10), peer.read())
            .await
            .map_err(|_| Error::new("HELLO timeout"))??;
        let msg = serializer.deserialize(hello)?;
        let hello = msg
            .as_any()
            .downcast_ref::<wampproto::messages::hello::Hello>()
            .ok_or_else(|| Error::new("expected HELLO"))?;
        let realm = self.realms.lock().unwrap().get(&hello.realm).cloned();
        let Some(realm) = realm else {
            peer.write(serializer.serialize(&wampproto::messages::abort::Abort {
                details: HashMap::new(),
                reason: "wamp.error.no_such_realm".into(),
                args: None,
                kwargs: None,
            })?)
            .await?;
            return Err(Error::new("no such realm"));
        };
        let factory = self
            .authentication_override
            .clone()
            .unwrap_or_else(|| realm.lock().unwrap().config.authentication.clone());
        let auth = factory();
        let meta_api = realm.lock().unwrap().config.meta_api;
        let mut acceptor = Acceptor::new(serializer.clone(), auth).with_session_meta_api(meta_api);
        let response = acceptor.receive_message(msg.as_ref())?;
        let mut data = serializer.serialize(response.as_ref())?;
        peer.write(std::mem::take(&mut data)).await?;

        while acceptor.session_details().is_err() {
            let data = tokio::time::timeout(Duration::from_secs(10), peer.read())
                .await
                .map_err(|_| Error::new("authentication timeout"))??;
            let (response, _) = acceptor.receive(data)?;
            peer.write(response).await?;
        }

        let details = acceptor.session_details()?.clone();
        self.run_established(realm, peer, serializer, details, authenticated)
            .await
    }

    async fn run_established(
        &self,
        realm: Arc<Mutex<Realm>>,
        peer: Arc<dyn Peer>,
        serializer: Box<dyn Serializer>,
        details: SessionDetails,
        authenticated: Option<tokio::sync::watch::Sender<Option<SessionDetails>>>,
    ) -> Result<(), Error> {
        let id = details.id;
        let metadata = details.clone();
        let attachment = Arc::new(());
        let (outgoing, mut incoming) = mpsc::channel::<Vec<u8>>(256);
        {
            let mut realm = realm.lock().unwrap();
            realm.broker.add_session(details.clone())?;

            if let Err(err) = realm.dealer.add_session(details.clone()) {
                let _ = realm.broker.remove_session(id);
                return Err(err.into());
            }

            realm.clients.insert(
                id,
                Client {
                    attachment: attachment.clone(),
                    details,
                    serializer: serializer.clone(),
                    outgoing,
                },
            );

            if realm.config.meta_api {
                realm.meta_event(id, true);
            }
        }

        let attachment_guard = Attachment {
            attachment,
            realm: realm.clone(),
            id,
            peer: peer.clone(),
        };

        if let Some(authenticated) = authenticated {
            authenticated.send_if_modified(|current| {
                if current.is_none() {
                    *current = Some(metadata);
                    true
                } else {
                    false
                }
            });
        }

        let _keepalive = self.keepalive.map(|(interval, timeout)| {
            let peer = peer.clone();
            AbortTask(tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    if let Err(error) = peer.ping(Some(timeout)).await {
                        let _ = peer.close().await;
                        return Err(error);
                    }
                }
            }))
        });

        let output_peer = peer.clone();
        let mut writer = AbortTask(tokio::spawn(async move {
            while let Some(data) = incoming.recv().await {
                output_peer.write(data).await?;
            }

            Ok::<(), Error>(())
        }));
        let result = loop {
            let data = tokio::select! {
                data = peer.read() => data,
                _ = &mut writer.0 => {
                    break Err(Error::new("writer stopped"));
                }
            };
            let msg = match data.and_then(|v| serializer.deserialize(v).map_err(Error::from)) {
                Ok(msg) => msg,
                Err(err) => break Err(err),
            };
            let policy = {
                let realm = realm.lock().unwrap();
                let code = match msg.message_type() {
                    Value::Int(code) => code,
                    _ => 0,
                };

                if matches!(code, 16 | 32 | 48 | 64) {
                    let wire = msg.marshal();
                    let uri = match wire.get(3) {
                        Some(Value::Str(uri)) => uri.as_str(),
                        _ => "",
                    };
                    realm.clients.get(&id).and_then(|client| {
                        let allowed = realm
                            .config
                            .roles
                            .get(&client.details.auth_role)
                            .is_some_and(|permissions| permissions.iter().any(|p| p.allows(code, uri)));
                        if allowed {
                            None
                        } else {
                            realm
                                .config
                                .authorizer
                                .clone()
                                .map(|policy| (policy, client.details.clone()))
                        }
                    })
                } else {
                    None
                }
            };
            let dynamic_authorized = policy.is_some_and(|(policy, details)| policy(&details, msg.as_ref()));
            let result = {
                let mut realm = realm.lock().unwrap();

                if !realm
                    .clients
                    .get(&id)
                    .is_some_and(|client| Arc::ptr_eq(&client.attachment, &attachment_guard.attachment))
                {
                    break Err(Error::new("session detached"));
                }

                realm.dispatch(id, msg.as_ref(), dynamic_authorized)
            };

            match result {
                Ok(true) => {}
                Ok(false) => break Ok(()),
                Err(err) => break Err(err),
            }
        };
        attachment_guard.detach();
        // Drain queued messages (notably GOODBYE) without waiting forever for blocked peers.
        if !writer.0.is_finished()
            && tokio::time::timeout(Duration::from_secs(1), &mut writer.0)
                .await
                .is_err()
        {
            writer.0.abort();
        }

        result
    }

    pub fn close(&self) {
        let mut realms = self.realms.lock().unwrap();

        for realm in realms.values() {
            let mut realm = realm.lock().unwrap();
            let goodbye = Goodbye {
                details: HashMap::new(),
                reason: "wamp.close.system_shutdown".into(),
            };
            let ids: Vec<_> = realm.clients.keys().copied().collect();

            for id in ids {
                let _ = realm.deliver(id, &goodbye);
                realm.detach(id);
            }
        }

        realms.clear();
    }
}

pub fn serializer(id: wampproto::transports::rawsocket::SerializerID) -> Box<dyn Serializer> {
    use wampproto::transports::rawsocket::SerializerID;

    match id {
        SerializerID::JSON => JSONSerializerSpec.serializer(),
        SerializerID::CBOR => CBORSerializerSpec.serializer(),
        SerializerID::MSGPACK => MsgPackSerializerSpec.serializer(),
    }
}

impl Realm {
    fn meta_details(details: &SessionDetails) -> Value {
        Value::Dict(HashMap::from([
            ("session".into(), Value::Int(details.id)),
            ("authid".into(), Value::Str(details.authid.clone())),
            ("authrole".into(), Value::Str(details.auth_role.clone())),
            ("authmethod".into(), Value::Str(details.auth_method.clone())),
            ("authextra".into(), Value::Dict(details.auth_extra.clone())),
            ("authprovider".into(), Value::Str(String::new())),
        ]))
    }

    fn meta_event(&mut self, id: i64, joined: bool) {
        let Some(client) = self.clients.get(&id) else { return };
        let args = if joined {
            vec![Self::meta_details(&client.details)]
        } else {
            vec![
                Value::Int(id),
                Value::Str(client.details.authid.clone()),
                Value::Str(client.details.auth_role.clone()),
            ]
        };
        let message = Publish {
            request_id: 1,
            options: HashMap::from([("exclude_me".into(), Value::Bool(true))]),
            topic: if joined {
                "wamp.session.on_join"
            } else {
                "wamp.session.on_leave"
            }
            .into(),
            args: Some(args),
            kwargs: None,
        };

        if let Ok(publication) = self.broker.receive_publish(id, &message) {
            for delivery in publication.events {
                for recipient in delivery.recipients {
                    let _ = self.deliver(recipient, delivery.event.as_ref());
                }
            }
        }
    }

    fn meta_call(&mut self, caller: i64, call: &wampproto::messages::call::Call) -> Result<bool, Error> {
        const PROCEDURES: &[&str] = &[
            "wamp.session.count",
            "wamp.session.list",
            "wamp.session.get",
            "wamp.session.kill",
            "wamp.session.kill_by_authid",
            "wamp.session.kill_by_authrole",
            "wamp.session.kill_all",
        ];

        if !PROCEDURES.contains(&call.procedure.as_str()) {
            return Ok(false);
        }

        let args = call.args.as_deref().unwrap_or_default();
        let result = (|| -> Result<Vec<Value>, &str> {
            match call.procedure.as_str() {
                "wamp.session.count" | "wamp.session.list" => {
                    let roles = match args {
                        [] => None,
                        [Value::List(roles)] if roles.iter().all(|r| matches!(r, Value::Str(_))) => Some(roles),
                        _ => return Err("wamp.error.invalid_argument"),
                    };
                    let mut ids: Vec<_> = self
                        .clients
                        .values()
                        .filter(|c| {
                            roles.is_none_or(|roles| {
                                roles.is_empty() || roles.contains(&Value::Str(c.details.auth_role.clone()))
                            })
                        })
                        .map(|c| c.details.id)
                        .collect();
                    ids.sort();

                    if call.procedure.ends_with("count") {
                        Ok(vec![Value::Int(ids.len() as i64)])
                    } else {
                        Ok(vec![Value::List(ids.into_iter().map(Value::Int).collect())])
                    }
                }
                "wamp.session.get" => {
                    let id = match args {
                        [Value::Int(id)] => *id,
                        [Value::UInt(id)] => i64::try_from(*id).map_err(|_| "wamp.error.invalid_argument")?,
                        _ => return Err("wamp.error.invalid_argument"),
                    };
                    self.clients
                        .get(&id)
                        .map(|c| vec![Self::meta_details(&c.details)])
                        .ok_or("wamp.error.no_such_session")
                }
                _ => {
                    let targets: Vec<i64> = match call.procedure.as_str() {
                        "wamp.session.kill" => {
                            let id = match args {
                                [Value::Int(id)] => *id,
                                [Value::UInt(id)] => i64::try_from(*id).map_err(|_| "wamp.error.invalid_argument")?,
                                _ => return Err("wamp.error.invalid_argument"),
                            };

                            if id == caller || !self.clients.contains_key(&id) {
                                return Err("wamp.error.no_such_session");
                            }

                            vec![id]
                        }
                        "wamp.session.kill_by_authid" | "wamp.session.kill_by_authrole" => {
                            let value = match args {
                                [Value::Str(value)] => value,
                                _ => return Err("wamp.error.invalid_argument"),
                            };
                            self.clients
                                .values()
                                .filter(|c| {
                                    c.details.id != caller
                                        && if call.procedure.ends_with("authid") {
                                            &c.details.authid == value
                                        } else {
                                            &c.details.auth_role == value
                                        }
                                })
                                .map(|c| c.details.id)
                                .collect()
                        }
                        _ => {
                            if !args.is_empty() {
                                return Err("wamp.error.invalid_argument");
                            }

                            self.clients.keys().filter(|id| **id != caller).copied().collect()
                        }
                    };
                    let kwargs = call.kwargs.as_ref();
                    let reason = match kwargs.and_then(|k| k.get("reason")) {
                        None => "wamp.close.killed".into(),
                        Some(Value::Str(s)) => s.clone(),
                        _ => return Err("wamp.error.invalid_argument"),
                    };
                    let mut details = HashMap::new();

                    if let Some(value) = kwargs.and_then(|k| k.get("message")) {
                        if !matches!(value, Value::Str(_)) {
                            return Err("wamp.error.invalid_argument");
                        }

                        details.insert("message".into(), value.clone());
                    }

                    for id in &targets {
                        let _ = self.deliver(
                            *id,
                            &Goodbye {
                                details: details.clone(),
                                reason: reason.clone(),
                            },
                        );
                        self.detach(*id);
                    }

                    if call.procedure == "wamp.session.kill" {
                        Ok(vec![])
                    } else {
                        Ok(vec![Value::List(targets.into_iter().map(Value::Int).collect())])
                    }
                }
            }
        })();

        match result {
            Ok(args) => self.deliver(
                caller,
                &wampproto::messages::result::Result_ {
                    request_id: call.request_id,
                    details: HashMap::new(),
                    args: Some(args),
                    kwargs: None,
                },
            )?,
            Err(uri) => self.deliver(
                caller,
                &ProtocolError {
                    message_type: Value::Int(48),
                    request_id: call.request_id,
                    options: HashMap::new(),
                    uri: uri.into(),
                    args: None,
                    kwargs: None,
                },
            )?,
        }

        Ok(true)
    }
}

impl Router {
    pub fn realm_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.realms.lock().unwrap().keys().cloned().collect();
        names.sort();
        names
    }

    pub fn has_role(&self, name: &str, role: &str) -> Result<bool, Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        Ok(realm.lock().unwrap().config.roles.contains_key(role))
    }

    pub fn enable_meta_api(&self, name: &str) -> Result<(), Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        realm.lock().unwrap().config.meta_api = true;
        Ok(())
    }

    pub fn set_authorizer(&self, name: &str, authorizer: Authorizer) -> Result<(), Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        realm.lock().unwrap().config.authorizer = Some(authorizer);
        Ok(())
    }

    pub fn add_role(&self, realm: &str, name: String, permissions: Vec<Permission>) -> Result<(), Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(realm)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        let mut realm = realm.lock().unwrap();

        if realm.config.roles.contains_key(&name) {
            return Err(Error::new("role already exists"));
        }

        realm.config.roles.insert(name, permissions);
        Ok(())
    }

    pub fn remove_role(&self, realm: &str, name: &str) -> Result<(), Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(realm)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        realm
            .lock()
            .unwrap()
            .config
            .roles
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| Error::new("no such role"))
    }

    pub fn remove_realm(&self, name: &str) -> Result<(), Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .remove(name)
            .ok_or_else(|| Error::new("no such realm"))?;
        let mut realm = realm.lock().unwrap();
        let ids: Vec<_> = realm.clients.keys().copied().collect();

        for id in ids {
            let _ = realm.deliver(
                id,
                &Goodbye {
                    details: HashMap::new(),
                    reason: "wamp.close.close_realm".into(),
                },
            );
            realm.detach(id);
        }

        Ok(())
    }
}

struct Attachment {
    attachment: Arc<()>,
    realm: Arc<Mutex<Realm>>,
    id: i64,
    peer: Arc<dyn Peer>,
}

impl Attachment {
    fn detach(&self) {
        let mut realm = self.realm.lock().unwrap();

        if realm
            .clients
            .get(&self.id)
            .is_some_and(|client| Arc::ptr_eq(&client.attachment, &self.attachment))
        {
            realm.detach(self.id);
        }
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.detach();
        let peer = self.peer.clone();

        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = peer.close().await;
            });
        }
    }
}

struct AbortTask(tokio::task::JoinHandle<Result<(), Error>>);

impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Router {
    /// Trusted in-process attachment. This bypasses network authentication;
    /// the embedding application explicitly supplies the local identity/role.
    pub async fn connect_internal(
        &self,
        realm_name: &str,
        authid: &str,
        role: &str,
        spec: Box<dyn SerializerSpec>,
    ) -> Result<Session, Error> {
        let (peer, details) = self
            .connect_internal_peer(realm_name, authid, role, spec.clone(), 256)
            .await?;
        Ok(Session::new(details, peer, spec.serializer()))
    }

    /// Open a trusted local peer without starting the client's receive loop.
    pub async fn connect_internal_peer(
        &self,
        realm_name: &str,
        authid: &str,
        role: &str,
        spec: Box<dyn SerializerSpec>,
        capacity: usize,
    ) -> Result<(Box<dyn Peer>, crate::SessionDetails), Error> {
        let details = SessionDetails::new(
            wampproto::idgen::generate_session_id()?,
            realm_name.into(),
            authid.into(),
            role.into(),
            false,
        )
        .with_authentication(
            "internal".into(),
            HashMap::new(),
            HashMap::new(),
            wampproto::authenticators::wampcra::utcnow(),
        );
        self.connect_internal_peer_with_details(details, spec, capacity).await
    }

    /// Attach an already authenticated transport while preserving its session identity.
    pub async fn connect_internal_peer_with_details(
        &self,
        details: SessionDetails,
        spec: Box<dyn SerializerSpec>,
        capacity: usize,
    ) -> Result<(Box<dyn Peer>, crate::SessionDetails), Error> {
        if !(wampproto::idgen::ID_MIN..=wampproto::idgen::ID_MAX).contains(&details.id) {
            return Err(Error::new("invalid session ID"));
        }

        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(&details.realm)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        let (client, server) = MemoryPeer::pair(capacity);
        let router = self.clone();
        let serializer = spec.serializer();
        let metadata = details.clone();
        let (ready, mut waiting) = tokio::sync::watch::channel(None);
        tokio::spawn(async move {
            let peer: Arc<dyn Peer> = Arc::from(server);
            let _ = router
                .run_established(realm, peer, serializer, metadata, Some(ready))
                .await;
        });
        waiting
            .wait_for(|value| value.is_some())
            .await
            .map_err(|_| Error::new("internal attachment failed"))?;
        Ok((client, crate::SessionDetails::from_protocol(&details)))
    }

    pub fn kill_session(&self, realm_name: &str, id: i64, reason: &str) -> Result<(), Error> {
        let realm = self
            .realms
            .lock()
            .unwrap()
            .get(realm_name)
            .cloned()
            .ok_or_else(|| Error::new("no such realm"))?;
        let mut realm = realm.lock().unwrap();

        if !realm.clients.contains_key(&id) {
            return Err(Error::new("no such session"));
        }

        realm.deliver(
            id,
            &Goodbye {
                details: HashMap::new(),
                reason: reason.into(),
            },
        )?;
        realm.detach(id);
        Ok(())
    }
}
