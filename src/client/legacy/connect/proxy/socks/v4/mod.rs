mod errors;
pub use errors::*;

mod messages;
use messages::*;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::Uri;
use hyper::rt::{Read, Write};
use tower_service::Service;

use pin_project_lite::pin_project;

/// TODO
#[derive(Debug)]
pub struct SocksV4<C> {
    inner: C,
    config: SocksConfig,
}

#[derive(Debug, Clone)]
struct SocksConfig {
    proxy: Uri,

    local_dns: bool,
    optimistic: bool,
}

pin_project! {
    // Not publicly exported (so missing_docs doesn't trigger).
    //
    // We return this `Future` instead of the `Pin<Box<dyn Future>>` directly
    // so that users don't rely on it fitting in a `Pin<Box<dyn Future>>` slot
    // (and thus we can change the type in the future).
    #[must_use = "futures do nothing unless polled"]
    #[allow(missing_debug_implementations)]
    pub struct Handshaking<F, T, E> {
        #[pin]
        fut: BoxHandshaking<T, E>,
        _marker: std::marker::PhantomData<F>
    }
}

type BoxHandshaking<T, E> = Pin<Box<dyn Future<Output = Result<T, super::SocksError<E>>> + Send>>;

impl<C> SocksV4<C> {
    pub fn new(proxy_dst: Uri, connector: C) -> Self {
        Self {
            inner: connector,
            config: SocksConfig::new(proxy_dst),
        }
    }
}

impl SocksConfig {
    pub fn new(proxy: Uri) -> Self {
        Self {
            proxy,

            local_dns: false,
            optimistic: false,
        }
    }

    async fn execute<T, E>(
        self,
        mut conn: T,
        host: String,
        port: u16,
    ) -> Result<T, super::SocksError<E>>
    where
        T: Read + Write + Unpin,
    {
        todo!()
    }
}
