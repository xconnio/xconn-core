use super::{
    rawsocket::{BoxStream, server_handshake},
    router::{Router, serializer},
};
use crate::Error;
use std::time::Duration;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{mpsc, watch},
};
use wampproto::types::SessionDetails;

pub struct AuthenticatedStream {
    pub stream: BoxStream,
    pub session: SessionDetails,
}

pub async fn serve_stream(
    router: Router,
    stream: BoxStream,
    authenticated: watch::Sender<Option<SessionDetails>>,
    raw: mpsc::Sender<AuthenticatedStream>,
) -> Result<(), Error> {
    let mut stream = BufReader::new(stream);
    let first = tokio::time::timeout(Duration::from_secs(10), stream.fill_buf())
        .await
        .map_err(|_| Error::new("stream classification timeout"))?
        .map_err(|e| Error::new(e.to_string()))?
        .first()
        .copied()
        .ok_or_else(|| Error::new("empty stream"))?;
    if first == wampproto::transports::rawsocket::MAGIC {
        let (peer, id) = tokio::time::timeout(Duration::from_secs(10), server_handshake(Box::new(stream)))
            .await
            .map_err(|_| Error::new("stream handshake timeout"))??;
        router.accept_notified(peer, serializer(id), authenticated).await
    } else {
        let mut auth = authenticated.subscribe();
        let details = tokio::time::timeout(Duration::from_secs(5), auth.wait_for(|v| v.is_some()))
            .await
            .map_err(|_| Error::new("raw stream authentication timeout"))?
            .map_err(|_| Error::new("connection closed"))?
            .clone()
            .unwrap();
        let incoming = AuthenticatedStream {
            stream: Box::new(stream),
            session: details,
        };
        #[cfg(feature = "services")]
        if let Some(routing) = router.stream_routing() {
            return routing.forward(incoming).await;
        }
        raw.send(incoming)
            .await
            .map_err(|_| Error::new("raw stream receiver closed"))
    }
}
