mod messages;
use messages::*;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use http::Uri;
use hyper::rt::{Read, Write};
use tower_service::Service;

use pin_project_lite::pin_project;

/// Tunnel Proxy via SOCKS 5 CONNECT
#[derive(Debug)]
pub struct Socks<C> {
    inner: C,
    config: SocksConfig,
}

#[derive(Debug, Clone)]
pub struct SocksConfig {
    proxy: Uri,
    proxy_auth: Option<(String, String)>,

    local_dns: bool,
    optimistic: bool,
}

enum State {
    SendingNegReq,
    ReadingNegRes,
    SendingAuthReq,
    ReadingAuthRes,
    SendingProxyReq,
    ReadingProxyRes,
}

#[derive(Debug)]
pub enum SocksError<C> {
    Inner(C),
    Io(std::io::Error),

    DnsFailure,
    MissingHost,
    MissingPort,
    HostTooLong,

    Auth(AuthError),
    Command(Status),

    Parsing(ParsingError),
    Serialize(SerializeError),
}

#[derive(Debug)]
pub enum AuthError {
    Unsupported,
    MethodMismatch,
    Failed,
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

type BoxHandshaking<T, E> = Pin<Box<dyn Future<Output = Result<T, SocksError<E>>> + Send>>;

impl SocksConfig {
    pub fn new(proxy: Uri) -> Self {
        Self {
            proxy,
            proxy_auth: None,

            local_dns: false,
            optimistic: false,
        }
    }

    /// Use User/Pass authentication method during handshake.
    ///
    /// Username and Password must be maximum of 255 characters each.
    /// 0 length strings are allowed despite RFC prohibiting it. This is done so that
    /// for compatablity with server implementations that require it for IP authentication.
    pub fn with_auth(mut self, user: String, pass: String) -> Self {
        self.proxy_auth = Some((user, pass));
        self
    }

    /// Resolve domain names locally on the client, rather than on the client.
    ///
    /// Disabled by default as local resolution of domain names can be detected as a
    /// DNS leak.
    pub fn local_dns(mut self, local_dns: bool) -> Self {
        self.local_dns = local_dns;
        self
    }

    /// Send all messages of the handshake optmistically (without waiting for server response).
    ///
    /// Typical SOCKS handshake with auithentication takes 3 round trips. Optimistic sending
    /// can reduce round trip times and dramatically increase speed of handshake at the cost of
    /// reduced portability; many server implementations do not support optimistic sending as it
    /// is not defined in the RFC (RFC 1928).
    ///
    /// Recommended to ensure connector works correctly without optimistic sending before trying
    /// with optimistic sending.
    pub fn send_optimistically(mut self, optimistic: bool) -> Self {
        self.optimistic = optimistic;
        self
    }

    pub fn build<C>(self, connector: C) -> Socks<C> {
        Socks {
            inner: connector,
            config: self,
        }
    }

    async fn execute<T, E>(self, mut conn: T, host: String, port: u16) -> Result<T, SocksError<E>>
    where
        T: Read + Write + Unpin,
    {
        let address = match host.parse::<IpAddr>() {
            Ok(ip) => Address::Socket(SocketAddr::new(ip, port)),
            Err(_) if host.len() <= 255 => {
                if !self.local_dns {
                    Address::Domain(host, port)
                } else {
                    let socket = (host, port)
                        .to_socket_addrs()?
                        .next()
                        .ok_or(SocksError::DnsFailure)?;

                    Address::Socket(socket)
                }
            }
            Err(_) => return Err(SocksError::HostTooLong),
        };

        let method = if self.proxy_auth.is_some() {
            AuthMethod::UserPass
        } else {
            AuthMethod::NoAuth
        };

        let mut buf: [u8; 513] = [0; 513];
        let mut state = State::SendingNegReq;

        loop {
            match state {
                State::SendingNegReq => {
                    let req = NegotiationReq(&method);
                    let n = req.write_to_buf(&mut buf[..])?;
                    crate::rt::write_all(&mut conn, &buf[..n]).await?;

                    if self.optimistic {
                        if method == AuthMethod::UserPass {
                            state = State::SendingAuthReq;
                        } else {
                            state = State::SendingProxyReq;
                        }
                    } else {
                        state = State::ReadingNegRes;
                    }
                }

                State::ReadingNegRes => {
                    let res: NegotiationRes = read_message(&mut conn, &mut buf).await?;

                    if res.0 == AuthMethod::NoneAcceptable {
                        return Err(AuthError::Unsupported.into());
                    }

                    if res.0 != method {
                        return Err(AuthError::MethodMismatch.into());
                    }

                    if self.optimistic {
                        if res.0 == AuthMethod::UserPass {
                            state = State::ReadingAuthRes;
                        } else {
                            state = State::ReadingProxyRes;
                        }
                    } else {
                        if res.0 == AuthMethod::UserPass {
                            state = State::SendingAuthReq;
                        } else {
                            state = State::SendingProxyReq;
                        }
                    }
                }

                State::SendingAuthReq => {
                    let (user, pass) = self.proxy_auth.as_ref().unwrap();
                    let req = AuthenticationReq(&user, &pass);
                    let n = req.write_to_buf(&mut buf[..])?;
                    crate::rt::write_all(&mut conn, &buf[..n]).await?;

                    if self.optimistic {
                        state = State::SendingProxyReq;
                    } else {
                        state = State::ReadingAuthRes;
                    }
                }

                State::ReadingAuthRes => {
                    let res: AuthenticationRes = read_message(&mut conn, &mut buf).await?;

                    if !res.0 {
                        return Err(AuthError::Failed.into());
                    }

                    state = State::SendingProxyReq;
                }

                State::SendingProxyReq => {
                    let req = ProxyReq(&address);
                    let n = req.write_to_buf(&mut buf[..])?;
                    crate::rt::write_all(&mut conn, &buf[..n]).await?;

                    if self.optimistic {
                        state = State::ReadingNegRes;
                    } else {
                        state = State::ReadingProxyRes;
                    }
                }

                State::ReadingProxyRes => {
                    let res: ProxyRes = read_message(&mut conn, &mut buf).await?;

                    if res.0 == Status::Success {
                        return Ok(conn);
                    } else {
                        return Err(res.0.into());
                    }
                }
            }
        }
    }
}

impl<C> Socks<C> {
    /// Create a new SOCKS CONNECT service
    pub fn builder(proxy: Uri) -> SocksConfig {
        SocksConfig::new(proxy)
    }
}

impl<C> Service<Uri> for Socks<C>
where
    C: Service<Uri>,
    C::Future: Send + 'static,
    C::Response: Read + Write + Unpin + Send + 'static,
    C::Error: Send + 'static,
{
    type Response = C::Response;
    type Error = SocksError<C::Error>;
    type Future = Handshaking<C::Future, C::Response, C::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(SocksError::Inner)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let config = self.config.clone();
        let connecting = self.inner.call(config.proxy.clone());

        let fut = async move {
            let host = dst.host().ok_or(SocksError::MissingHost)?.to_string();
            let port = dst.port().ok_or(SocksError::MissingPort)?.as_u16();
            let conn = connecting.await.map_err(SocksError::Inner)?;
            config.execute(conn, host, port).await
        };

        Handshaking {
            fut: Box::pin(fut),
            _marker: Default::default(),
        }
    }
}

impl<F, T, E> Future for Handshaking<F, T, E>
where
    F: Future<Output = Result<T, E>>,
{
    type Output = Result<T, SocksError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.project().fut.poll(cx)
    }
}

async fn read_message<T, M, C>(mut conn: &mut T, buf: &mut [u8]) -> Result<M, SocksError<C>>
where
    T: Read + Unpin,
    M: for<'a> TryFrom<&'a [u8], Error = ParsingError>,
{
    let mut n = 0;
    loop {
        let read = crate::rt::read(&mut conn, buf).await?;

        if read == 0 {
            return Err(
                std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected eof").into(),
            );
        }

        n += read;
        match M::try_from(&buf[..n]) {
            Err(ParsingError::Incomplete) => continue,
            Err(err) => return Err(err.into()),

            Ok(res) => return Ok(res),
        }
    }
}

impl<C> From<std::io::Error> for SocksError<C> {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl<C> From<ParsingError> for SocksError<C> {
    fn from(err: ParsingError) -> Self {
        Self::Parsing(err)
    }
}

impl<C> From<AuthError> for SocksError<C> {
    fn from(err: AuthError) -> Self {
        Self::Auth(err)
    }
}

impl<C> From<Status> for SocksError<C> {
    fn from(err: Status) -> Self {
        Self::Command(err)
    }
}

impl<C> From<SerializeError> for SocksError<C> {
    fn from(err: SerializeError) -> Self {
        Self::Serialize(err)
    }
}
