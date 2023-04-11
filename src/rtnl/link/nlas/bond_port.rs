// SPDX-License-Identifier: MIT
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{Nla, NlaBuffer},
    parsers::parse_i32,
    traits::Parseable,
    DecodeError,
};

use crate::constants::*;

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoBondPort {
    Prio(i32),
}

impl Nla for InfoBondPort {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::InfoBondPort::*;
        match *self {
            Prio(_)
                => 4,
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::InfoBondPort::*;
        match self {
            Prio(value)
             => NativeEndian::write_i32(buffer, *value),
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoBondPort::*;

        match self {
            Prio(_) => IFLA_BOND_SLAVE_PRIO,
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoBondPort {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoBondPort::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            IFLA_BOND_SLAVE_PRIO => Prio(
                parse_i32(payload)
                    .context("invalid IFLA_BOND_SLAVE_PRIO value")?,
            ),
            _ => return Err(format!("unknown NLA type {}", buf.kind()).into()),
        })
    }
}
