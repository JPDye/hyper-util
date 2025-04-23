mod v5;
pub use v5::{SocksV5, SocksV5Error};

mod v4;
pub use v4::{SocksV4, SocksV4Error};

#[derive(Debug)]
pub enum SocksError<C> {
    Inner(C),
    Io(std::io::Error),

    DnsFailure,
    MissingHost,
    MissingPort,
    HostTooLong,

    V4(SocksV4Error),
    V5(SocksV5Error),

    Parsing(ParsingError),
    Serialize(SerializeError),
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

impl<C> From<SerializeError> for SocksError<C> {
    fn from(err: SerializeError) -> Self {
        Self::Serialize(err)
    }
}

impl<C> From<SocksV4Error> for SocksError<C> {
    fn from(err: SocksV4Error) -> Self {
        Self::V4(err)
    }
}

impl<C> From<SocksV5Error> for SocksError<C> {
    fn from(err: SocksV5Error) -> Self {
        Self::V5(err)
    }
}
