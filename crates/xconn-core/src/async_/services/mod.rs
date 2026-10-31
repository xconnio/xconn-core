//! Optional reusable communication services. Applications own policy and storage.
pub mod attachment;
pub mod bridge;
pub mod discovery;
pub mod stream_broker;

pub(crate) mod backend;
#[cfg(any(feature = "quic", feature = "webtransport"))]
pub mod routing;
