use crate::async_::joiner::{RawSocketJoiner, WebSocketJoiner};
use crate::async_::session::Session;
use crate::common::types::{CBORSerializerSpec, Error, SerializerSpec};

use wampproto::authenticators::anonymous::AnonymousAuthenticator;
use wampproto::authenticators::authenticator::ClientAuthenticator;
use wampproto::authenticators::cryptosign::CryptoSignAuthenticator;
use wampproto::authenticators::ticket::TicketAuthenticator;
use wampproto::authenticators::wampcra::WAMPCRAAuthenticator;

#[derive(Clone)]
pub struct Client {
    pub(crate) serializer: Box<dyn SerializerSpec>,
    pub(crate) authenticator: Box<dyn ClientAuthenticator + Send + Sync>,
}

impl Client {
    pub fn new(serializer: Box<dyn SerializerSpec>, authenticator: Box<dyn ClientAuthenticator + Send + Sync>) -> Self {
        Self {
            serializer,
            authenticator,
        }
    }

    /// Run a backend until cancelled. Setup runs once after each connection and
    /// uses the ordinary Session API to restore registrations/subscriptions.
    /// Setup errors stop the backend; transport failures reconnect with backoff.
    #[cfg(feature = "services")]
    pub async fn serve<F, Fut>(&self, uri: &str, realm: &str, setup: F) -> Result<(), Error>
    where
        F: Fn(Session) -> Fut,
        Fut: Future<Output = Result<(), Error>>,
    {
        super::services::backend::run(
            || async { self.clone().connect(uri, realm).await.map(|session| (session, ())) },
            |session, ()| setup(session),
        )
        .await
    }

    pub async fn connect(self, uri: &str, realm: &str) -> Result<Session, Error> {
        self.connect_with_timeout(uri, realm, Some(std::time::Duration::from_secs(20)))
            .await
    }

    pub async fn connect_with_timeout(
        self,
        uri: &str,
        realm: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<Session, Error> {
        match timeout {
            Some(timeout) => tokio::time::timeout(timeout, self.connect_inner(uri, realm))
                .await
                .map_err(|_| Error::new("connection handshake timeout"))?,
            None => self.connect_inner(uri, realm).await,
        }
    }

    async fn connect_inner(self, uri: &str, realm: &str) -> Result<Session, Error> {
        if uri.starts_with("ws://") || uri.starts_with("wss://") || uri.starts_with("unix+ws://") {
            let serializer = self.serializer.serializer();
            let joiner = WebSocketJoiner::new(self.serializer, self.authenticator);
            let (peer, details) = joiner.join(uri, realm).await.map_err(|e| Error::new(e.to_string()))?;
            Ok(Session::new(details, peer, serializer))
        } else if uri.starts_with("rs://")
            || uri.starts_with("unix://")
            || uri.starts_with("unix+rs://")
            || uri.starts_with("tcp://")
        {
            let serializer = self.serializer.serializer();
            let joiner = RawSocketJoiner::new(self.serializer, self.authenticator);
            let (peer, details) = joiner.join(uri, realm).await.map_err(|e| Error::new(e.to_string()))?;
            Ok(Session::new(details, peer, serializer))
        } else {
            Err(Error::new("Invalid URI scheme".to_string()))
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self {
            serializer: Box::new(CBORSerializerSpec {}),
            authenticator: Box::new(AnonymousAuthenticator::new("", Default::default())),
        }
    }
}

pub async fn connect_anonymous(uri: &str, realm: &str) -> Result<Session, Error> {
    let client = Client::default();
    client.connect(uri, realm).await
}

pub async fn connect_ticket(uri: &str, realm: &str, authid: &str, ticket: &str) -> Result<Session, Error> {
    let serializer = Box::new(CBORSerializerSpec {});
    let authenticator = Box::new(TicketAuthenticator::new(authid, ticket, Default::default()));

    let client = Client::new(serializer, authenticator);
    client.connect(uri, realm).await
}

pub async fn connect_wampcra(uri: &str, realm: &str, authid: &str, secret: &str) -> Result<Session, Error> {
    let serializer = Box::new(CBORSerializerSpec {});
    let authenticator = Box::new(WAMPCRAAuthenticator::new(authid, secret, Default::default()));

    let client = Client::new(serializer, authenticator);
    client.connect(uri, realm).await
}

pub async fn connect_cryptosign(uri: &str, realm: &str, authid: &str, private_key_hex: &str) -> Result<Session, Error> {
    let serializer = Box::new(CBORSerializerSpec {});
    let authenticator = CryptoSignAuthenticator::try_new(authid, private_key_hex, Default::default())
        .map_err(|e| Error::new(e.to_string()))?;

    let client = Client::new(serializer, Box::new(authenticator));
    client.connect(uri, realm).await
}
