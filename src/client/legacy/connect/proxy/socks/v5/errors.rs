use super::Status;

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

#[derive(Debug)]
pub enum ParsingError {
    Incomplete,
    Other,
}

#[derive(Debug)]
pub enum SerializeError {
    WouldOverflow,
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
