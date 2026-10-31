//! Backend execution mechanics; applications use Client::serve or quic::run_backend.
use super::attachment::RetryPolicy;
use crate::{Error, async_::session::Session};

struct SessionOwner(Session, tokio::runtime::Handle);

impl Drop for SessionOwner {
    fn drop(&mut self) {
        let session = self.0.clone();
        self.1.spawn(async move {
            let _ = session.close().await;
        });
    }
}

pub(crate) async fn run<C, Connect, T, H, Handle>(mut connect: C, handle: H) -> Result<(), Error>
where
    C: FnMut() -> Connect,
    Connect: Future<Output = Result<(Session, T), Error>>,
    T: Clone,
    H: Fn(Session, T) -> Handle,
    Handle: Future<Output = Result<(), Error>>,
{
    let retry = RetryPolicy::default();
    let mut delay = retry.initial;
    loop {
        let (session, transport) = match connect().await {
            Ok(connected) => connected,
            Err(_) => {
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(retry.maximum);
                continue;
            }
        };
        let _owner = SessionOwner(session.clone(), tokio::runtime::Handle::current());
        tokio::select! {
            result = handle(session.clone(), transport.clone()) => {
                if let Err(error) = result {
                    let _ = session.close().await;
                    return Err(error);
                }
                session.wait_disconnect().await;
            }
            _ = session.wait_disconnect() => {},
        }
        let _ = session.close().await;
        drop(transport);
        delay = retry.initial;
        tokio::time::sleep(delay).await;
    }
}
