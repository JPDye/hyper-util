use super::super::{ParsingError, SerializeError};

use bytes::{Buf, BufMut};
use std::net::SocketAddrV4;

/// +-----+-----+----+----+----+----+----+----+-------------+------+------------+------+
/// |  VN |  CD | DSTPORT |        DSTIP      |    USERID   | NULL |   DOMAIN   | NULL |
/// +-----+-----+----+----+----+----+----+----+-------------+------+------------+------+
/// |  1  |  1  |    2    |         4         |   Variable  |  1   |  Variable  |   1  |
/// +-----+-----+----+----+----+----+----+----+-------------+------+------------+------+
///                                                                ^^^^^^^^^^^^^^^^^^^^^
///                                                      optional: only do IP is 0.0.0.X
#[derive(Debug)]
pub struct Request<'a>(&'a Address);

/// +-----+-----+----+----+----+----+----+----+
/// |  VN |  CD | DSTPORT |       DSTIP       |
/// +-----+-----+----+----+----+----+----+----+
/// |  1  |  1  |    2    |         4         |
/// +-----+-----+----+----+----+----+----+----+
///             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
///              ignore: only for SOCKSv4 BIND
#[derive(Debug)]
pub struct Response(Status, SocketAddrV4);

#[derive(Debug)]
pub enum Address {
    Socket(SocketAddrV4),
    Domain(String, u16),
}

#[repr(u8)]
#[derive(Debug)]
pub enum Status {
    Success = 90,
    Failed = 91,
    IdentFailure = 92,
    IdentMismatch = 93,
}

impl Request<'_> {
    pub fn write_to_buf<B: BufMut>(&self, mut buf: B) -> Result<usize, SerializeError> {
        match self.0 {
            Address::Socket(socket) => {
                if buf.remaining_mut() < 10 {
                    return Err(SerializeError::WouldOverflow);
                }

                buf.put_u8(0x04); // Version
                buf.put_u8(0x01); // CONNECT

                buf.put_u16(socket.port()); // Port
                buf.put_slice(&socket.ip().octets()); // IP

                buf.put_u8(0x00); // USERID
                buf.put_u8(0x00); // NULL

                Ok(9)
            }

            Address::Domain(domain, port) => {
                if buf.remaining_mut() < 10 + domain.len() + 1 {
                    return Err(SerializeError::WouldOverflow);
                }

                buf.put_u8(0x04); // Version
                buf.put_u8(0x01); // CONNECT

                buf.put_u16(*port); // IP
                buf.put_slice(&[0x00, 0x00, 0x00, 0xFF]); // Invalid IP

                buf.put_u8(0x00); // USERID
                buf.put_u8(0x00); // NULL

                buf.put_slice(domain.as_bytes()); // Domain
                buf.put_u8(0x00); // NULL

                Ok(10 + domain.len() + 1)
            }
        }
    }
}

impl TryFrom<&[u8]> for Response {
    type Error = ParsingError;

    fn try_from(mut buf: &[u8]) -> Result<Self, Self::Error> {
        if buf.remaining() < 8 {
            return Err(ParsingError::Incomplete);
        }

        if buf.get_u8() != 0x04 {
            return Err(ParsingError::Other);
        }

        let status = buf.get_u8().try_into()?;

        let addr = {
            let port = buf.get_u16();
            let mut ip = [0; 4];
            buf.copy_to_slice(&mut ip);

            SocketAddrV4::new(ip.into(), port)
        };

        Ok(Self(status, addr))
    }
}

impl TryFrom<u8> for Status {
    type Error = ParsingError;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Ok(match byte {
            90 => Self::Success,
            91 => Self::Failed,
            92 => Self::IdentFailure,
            93 => Self::IdentMismatch,
            _ => return Err(ParsingError::Other),
        })
    }
}
