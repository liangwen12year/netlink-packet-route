// SPDX-License-Identifier: MIT
use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_i32, parse_u16, parse_u32, parse_u8},
    traits::Parseable,
    DecodeError,
};

use crate::constants::*;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum SlaveState {
    ACTIVE,
    BACKUP,
    Other(u8),
}

impl From<u8> for SlaveState {
    fn from(value: u8) -> Self {
        use self::SlaveState::*;
        match value {
            IFLA_BOND_SLAVE_STATE_ACTIVE => ACTIVE,
            IFLA_BOND_SLAVE_STATE_BACKUP => BACKUP,
            _ => Other(value),
        }
    }
}

impl From<SlaveState> for u8 {
    fn from(value: SlaveState) -> Self {
        use self::SlaveState::*;
        match value {
            ACTIVE => IFLA_BOND_SLAVE_STATE_ACTIVE,
            BACKUP => IFLA_BOND_SLAVE_STATE_BACKUP,
            Other(other) => other,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum MiiStatus {
    UP,
    GOING_DOWN,
    DOWN,
    GOING_BACK,
    Other(u8),
}

impl From<u8> for MiiStatus {
    fn from(value: u8) -> Self {
        use self::MiiStatus::*;
        match value {
            IFLA_BOND_SLAVE_MII_STATUS_UP => UP,
            IFLA_BOND_SLAVE_MII_STATUS_GOING_DOWN => GOING_DOWN,
            IFLA_BOND_SLAVE_MII_STATUS_DOWN => DOWN,
            IFLA_BOND_SLAVE_MII_STATUS_GOING_BACK => GOING_BACK,
            _ => Other(value),
        }
    }
}

impl From<MiiStatus> for u8 {
    fn from(value: MiiStatus) -> Self {
        use self::MiiStatus::*;
        match value {
            UP => IFLA_BOND_SLAVE_MII_STATUS_UP,
            GOING_DOWN => IFLA_BOND_SLAVE_MII_STATUS_GOING_DOWN,
            DOWN => IFLA_BOND_SLAVE_MII_STATUS_DOWN,
            GOING_BACK => IFLA_BOND_SLAVE_MII_STATUS_GOING_BACK,
            Other(other) => other,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum InfoBondPort {
    LinkFailureCount(u32),
    MiiStatus(MiiStatus),
    PermHwaddr(Vec<u8>),
    Prio(i32),
    QueueId(u16),
    SlaveState(SlaveState),
    Other(DefaultNla),
}

impl Nla for InfoBondPort {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        eprintln!("infobondport value len");
        use self::InfoBondPort::*;
        match self {
            QueueId(_)
                => 2,
            LinkFailureCount(_) |
            Prio(_)
                => 4,
            PermHwaddr(ref bytes)
            => bytes.len(),
            MiiStatus(_) => 1,
            SlaveState(_) => 1,
            Other(nla)
                => nla.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        eprintln!("infobondport emit value");
        use self::InfoBondPort::*;
        match self {
           QueueId(ref value)
             => {
                eprintln!("+++++");
                eprintln!("{:?}", value);
                NativeEndian::write_u16(buffer, *value);
            }
             PermHwaddr(ref bytes)
             => buffer.copy_from_slice(bytes.as_slice()),
             Prio(ref value)
             => { eprintln!(">>>>>");
                  eprintln!("{:?}", value);
                NativeEndian::write_i32(buffer, *value);
                }
            LinkFailureCount(value)
             => NativeEndian::write_u32(buffer, *value),
             MiiStatus(state) => buffer[0] = (*state).into(),
             SlaveState(state) => buffer[0] = (*state).into(),
             Other(nla)
             => {eprintln!("******other****");
                nla.emit_value(buffer);}
        }
    }

    fn kind(&self) -> u16 {
        use self::InfoBondPort::*;
        eprintln!("infobondport kind");

        match self {
            LinkFailureCount(_) => IFLA_BOND_SLAVE_LINK_FAILURE_COUNT,
            MiiStatus(_) => IFLA_BOND_SLAVE_MII_STATUS,
            PermHwaddr(_) => IFLA_BOND_SLAVE_PERM_HWADDR,
            Prio(_) => IFLA_BOND_SLAVE_PRIO,
            QueueId(_) => IFLA_BOND_SLAVE_QUEUE_ID,
            SlaveState(_) => IFLA_BOND_SLAVE_STATE,
            Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for InfoBondPort {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::InfoBondPort::*;
        let payload = buf.value();
        eprintln!("before match");
        Ok(match buf.kind() {
            IFLA_BOND_SLAVE_LINK_FAILURE_COUNT => {
                LinkFailureCount(parse_u32(payload).context(
                    "invalid IFLA_BOND_SLAVE_LINK_FAILURE_COUNT value",
                )?)
            }
            IFLA_BOND_SLAVE_MII_STATUS => MiiStatus(
                parse_u8(payload)
                    .context("invalid IFLA_BOND_SLAVE_MII_STATUS value")?
                    .into(),
            ),
            IFLA_BOND_SLAVE_PERM_HWADDR => PermHwaddr(payload.to_vec()),
            IFLA_BOND_SLAVE_PRIO => {
                eprintln!("*******parsing prio********");
                Prio(
                    parse_i32(payload)
                        .context("invalid IFLA_BOND_SLAVE_PRIO value")?,
                )
            }
            IFLA_BOND_SLAVE_QUEUE_ID => QueueId(
                parse_u16(payload)
                    .context("invalid IFLA_BOND_SLAVE_QUEUE_ID value")?,
            ),
            IFLA_BOND_SLAVE_STATE => SlaveState(
                parse_u8(payload)
                    .context("invalid IFLA_BOND_SLAVE_STATE value")?
                    .into(),
            ),
            kind => Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown NLA type {kind}"))?,
            ),
        })
    }
}
