//! Authorized stream routing independent of application headers and realm layout.
use crate::{Error, async_::rawsocket::BoxStream};
use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
};
use wampproto::types::SessionDetails;

/// Opens a new stream on an already authenticated destination connection.
/// The caller of `open` supplies its own deadline; cancelling it drops this future.
pub type StreamOpener = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<BoxStream, Error>> + Send>> + Send + Sync>;

/// Authorizes an authenticated source, destination key, and authenticated target.
/// Every open is checked. The broker imposes no identity or realm conventions.
pub type RelayPolicy = Arc<dyn Fn(&SessionDetails, &str, &SessionDetails) -> bool + Send + Sync>;

struct Destination {
    identity: SessionDetails,
    open: StreamOpener,
}

type Destinations = Mutex<HashMap<String, Arc<Destination>>>;

/// Registry of authenticated destinations. The embedding application admits and
/// registers destinations; this service does not expose an enrollment protocol.
#[derive(Clone)]
pub struct StreamBroker {
    destinations: Arc<Destinations>,
    authorize: RelayPolicy,
}

impl StreamBroker {
    pub fn new(authorize: RelayPolicy) -> Self {
        Self {
            destinations: Arc::new(Mutex::new(HashMap::new())),
            authorize,
        }
    }

    /// Replaces the destination under this key. Keep the registration alive for
    /// the connection's lifetime. Dropping an older registration cannot remove
    /// its replacement. Existing streams remain owned by their forwarding tasks.
    pub fn register(
        &self,
        key: impl Into<String>,
        identity: SessionDetails,
        open: StreamOpener,
    ) -> Result<DestinationRegistration, Error> {
        let key = key.into();
        if key.is_empty() {
            return Err(Error::new("stream destination key must not be empty"));
        }
        let destination = Arc::new(Destination { identity, open });
        self.destinations
            .lock()
            .unwrap()
            .insert(key.clone(), destination.clone());
        Ok(DestinationRegistration {
            destinations: Arc::downgrade(&self.destinations),
            key,
            destination,
        })
    }

    /// The source identity must come from the authenticated listener, never an
    /// application header. Policy runs before opening any destination stream.
    /// An open already in progress may finish after its registration is removed.
    pub async fn open(&self, source: &SessionDetails, key: &str) -> Result<BoxStream, Error> {
        let destination = self
            .destinations
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| Error::new("stream destination is unavailable"))?;
        if !(self.authorize)(source, key, &destination.identity) {
            return Err(Error::new("stream relay is not authorized"));
        }
        (destination.open)().await
    }

    pub async fn relay(&self, source: &SessionDetails, key: &str, stream: BoxStream) -> Result<(u64, u64), Error> {
        let destination = self.open(source, key).await?;
        forward(stream, destination).await
    }
}

/// Owns one registry entry, not the underlying connection or active streams.
/// The application closes those resources with their connection lifecycle.
pub struct DestinationRegistration {
    destinations: Weak<Destinations>,
    key: String,
    destination: Arc<Destination>,
}

impl DestinationRegistration {
    pub fn close(&self) {
        let Some(destinations) = self.destinations.upgrade() else {
            return;
        };
        let mut destinations = destinations.lock().unwrap();
        if destinations
            .get(&self.key)
            .is_some_and(|current| Arc::ptr_eq(current, &self.destination))
        {
            destinations.remove(&self.key);
        }
    }
}

impl Drop for DestinationRegistration {
    fn drop(&mut self) {
        self.close();
    }
}

/// Copies opaque bytes with bounded buffers and backpressure. EOF half-closes
/// the opposite writer while allowing the remaining reply to drain. Dropping
/// this future releases both streams; the application owns its forwarding task.
pub async fn forward(mut source: BoxStream, mut destination: BoxStream) -> Result<(u64, u64), Error> {
    tokio::io::copy_bidirectional(&mut source, &mut destination)
        .await
        .map_err(|error| Error::new(error.to_string()))
}
