//! Stream-routing policy; listeners own routing workers and registrations.
use super::stream_broker::{RelayPolicy, StreamBroker, StreamOpener};
use crate::{Error, async_::multiplex::AuthenticatedStream};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio::io::AsyncWriteExt;
use wampproto::types::SessionDetails;

pub struct RoutedStream {
    incoming: AuthenticatedStream,
    destination: String,
    prefix: Vec<u8>,
    failure: Vec<u8>,
}

impl AuthenticatedStream {
    /// Route this authenticated stream after reading an application header.
    pub fn route_to(self, destination: impl Into<String>) -> RoutedStream {
        RoutedStream {
            incoming: self,
            destination: destination.into(),
            prefix: Vec::new(),
            failure: Vec::new(),
        }
    }
}

impl RoutedStream {
    /// Replay an existing application's header to the selected destination.
    pub fn with_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.prefix = prefix;
        self
    }

    /// Optional application-protocol reply when opening the destination fails.
    pub fn with_failure(mut self, response: Vec<u8>) -> Self {
        self.failure = response;
        self
    }
}

type Destination = Arc<dyn Fn(&SessionDetails) -> Option<String> + Send + Sync>;
type Route =
    Arc<dyn Fn(AuthenticatedStream) -> Pin<Box<dyn Future<Output = Result<RoutedStream, Error>> + Send>> + Send + Sync>;

/// Install once on a router before starting its listeners. Policy chooses
/// destinations and decodes headers; XConn owns connections and forwarding.
#[derive(Clone)]
pub struct StreamRouting {
    broker: StreamBroker,
    destination: Destination,
    route: Route,
}

impl StreamRouting {
    pub fn new<D, R, Fut>(destination: D, route: R, authorize: RelayPolicy) -> Self
    where
        D: Fn(&SessionDetails) -> Option<String> + Send + Sync + 'static,
        R: Fn(AuthenticatedStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RoutedStream, Error>> + Send + 'static,
    {
        Self {
            broker: StreamBroker::new(authorize),
            destination: Arc::new(destination),
            route: Arc::new(move |incoming| Box::pin(route(incoming))),
        }
    }

    pub(crate) fn register(
        &self,
        identity: SessionDetails,
        open: StreamOpener,
    ) -> Result<Option<super::stream_broker::DestinationRegistration>, Error> {
        (self.destination)(&identity)
            .map(|key| self.broker.register(key, identity, open))
            .transpose()
    }

    pub(crate) async fn forward(&self, incoming: AuthenticatedStream) -> Result<(), Error> {
        let mut routed = (self.route)(incoming).await?;
        let mut target = match self.broker.open(&routed.incoming.session, &routed.destination).await {
            Ok(target) => target,
            Err(error) => {
                if !routed.failure.is_empty() {
                    let _ = routed.incoming.stream.write_all(&routed.failure).await;
                    let _ = routed.incoming.stream.shutdown().await;
                }
                return Err(error);
            }
        };
        target
            .write_all(&routed.prefix)
            .await
            .map_err(|error| Error::new(error.to_string()))?;
        super::stream_broker::forward(routed.incoming.stream, target).await?;
        Ok(())
    }
}
