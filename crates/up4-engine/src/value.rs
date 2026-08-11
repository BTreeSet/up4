//! Control-plane scalars: the closed set of value shapes up4's tables use.
//!
//! Every string an operator types (`10.0.0.0/24`, `aa:bb:cc:dd:ee:01`, `0x1f`)
//! enters the switch through exactly one function here and leaves it as a
//! [`TypedVal`]. Nothing downstream parses text.

use serde::{Deserialize, Serialize};
use std::{fmt, net::Ipv4Addr, str::FromStr};

/// A 48-bit Ethernet address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// The all-ones broadcast address.
    pub const BROADCAST: Self = Self([0xff; 6]);

    /// Wrap six octets in wire order.
    #[must_use]
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// The octets in wire order.
    #[must_use]
    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// True for the broadcast and multicast group addresses.
    #[must_use]
    pub const fn is_group(self) -> bool {
        self.0[0] & 1 == 1
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl FromStr for MacAddr {
    type Err = ValueError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ValueError::Malformed {
            kind: ValKind::Mac,
            text: s.to_owned(),
        };
        let mut octets = [0u8; 6];
        let mut parts = s.split([':', '-']);
        for slot in &mut octets {
            *slot = u8::from_str_radix(parts.next().ok_or_else(bad)?, 16).map_err(|_| bad())?;
        }
        if parts.next().is_some() {
            return Err(bad());
        }
        Ok(Self(octets))
    }
}

/// The shape of a table key field or action parameter.
///
/// Carried in the static [`crate::TableSchema`] so `up4ctl` can tell an
/// operator what to type before they type it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValKind {
    /// An 8-bit unsigned integer, decimal or `0x`-prefixed.
    U8,
    /// A 16-bit unsigned integer, decimal or `0x`-prefixed.
    U16,
    /// A 32-bit unsigned integer, decimal or `0x`-prefixed.
    U32,
    /// An Ethernet address, `aa:bb:cc:dd:ee:ff`.
    Mac,
    /// An IPv4 address, dotted quad.
    Ipv4,
}

impl ValKind {
    /// How to spell a value of this kind, for help text.
    #[must_use]
    pub const fn syntax(self) -> &'static str {
        match self {
            Self::U8 => "u8 (e.g. 64 or 0x40)",
            Self::U16 => "u16 (e.g. 1 or 0x1f)",
            Self::U32 => "u32",
            Self::Mac => "mac (aa:bb:cc:dd:ee:ff)",
            Self::Ipv4 => "ipv4 (10.0.0.1)",
        }
    }
}

/// A scalar control-plane value, always of a known [`ValKind`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TypedVal {
    /// See [`ValKind::U8`].
    U8(u8),
    /// See [`ValKind::U16`].
    U16(u16),
    /// See [`ValKind::U32`].
    U32(u32),
    /// See [`ValKind::Mac`].
    Mac(MacAddr),
    /// See [`ValKind::Ipv4`].
    Ipv4(Ipv4Addr),
}

/// Why a control-plane value could not be accepted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueError {
    /// The text is not a value of the expected kind.
    Malformed {
        /// Kind that was expected.
        kind: ValKind,
        /// Text that was offered.
        text: String,
    },
    /// A value of the wrong kind was supplied where `expected` was required.
    Mismatched {
        /// Kind the table demands.
        expected: ValKind,
        /// Kind that was offered.
        got: ValKind,
    },
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { kind, text } => {
                write!(f, "{text:?} is not a valid {}", kind.syntax())
            }
            Self::Mismatched { expected, got } => {
                write!(f, "expected {}, got {got:?}", expected.syntax())
            }
        }
    }
}

impl std::error::Error for ValueError {}

impl TypedVal {
    /// The kind of this value.
    #[must_use]
    pub const fn kind(self) -> ValKind {
        match self {
            Self::U8(_) => ValKind::U8,
            Self::U16(_) => ValKind::U16,
            Self::U32(_) => ValKind::U32,
            Self::Mac(_) => ValKind::Mac,
            Self::Ipv4(_) => ValKind::Ipv4,
        }
    }

    /// Parse `text` as a value of `kind`. The single text gate.
    pub fn parse(kind: ValKind, text: &str) -> Result<Self, ValueError> {
        let bad = || ValueError::Malformed {
            kind,
            text: text.to_owned(),
        };
        Ok(match kind {
            ValKind::U8 => Self::U8(
                parse_int(text)
                    .and_then(|v| u8::try_from(v).ok())
                    .ok_or_else(bad)?,
            ),
            ValKind::U16 => Self::U16(
                parse_int(text)
                    .and_then(|v| u16::try_from(v).ok())
                    .ok_or_else(bad)?,
            ),
            ValKind::U32 => Self::U32(
                parse_int(text)
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or_else(bad)?,
            ),
            ValKind::Mac => Self::Mac(text.parse().map_err(|_| bad())?),
            ValKind::Ipv4 => Self::Ipv4(text.parse().map_err(|_| bad())?),
        })
    }

    /// Require this value to be of `expected` kind.
    pub fn require(self, expected: ValKind) -> Result<Self, ValueError> {
        if self.kind() == expected {
            Ok(self)
        } else {
            Err(ValueError::Mismatched {
                expected,
                got: self.kind(),
            })
        }
    }

    /// The value as a `u16`, if it is one.
    #[must_use]
    pub const fn as_u16(self) -> Option<u16> {
        match self {
            Self::U16(v) => Some(v),
            _ => None,
        }
    }

    /// The value as a MAC address, if it is one.
    #[must_use]
    pub const fn as_mac(self) -> Option<MacAddr> {
        match self {
            Self::Mac(v) => Some(v),
            _ => None,
        }
    }

    /// The value as an IPv4 address, if it is one.
    #[must_use]
    pub const fn as_ipv4(self) -> Option<Ipv4Addr> {
        match self {
            Self::Ipv4(v) => Some(v),
            _ => None,
        }
    }
}

impl fmt::Display for TypedVal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U8(v) => write!(f, "{v}"),
            Self::U16(v) => write!(f, "{v}"),
            Self::U32(v) => write!(f, "{v}"),
            Self::Mac(v) => write!(f, "{v}"),
            Self::Ipv4(v) => write!(f, "{v}"),
        }
    }
}

/// Decimal, or hexadecimal with an `0x` prefix.
fn parse_int(text: &str) -> Option<u64> {
    match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_round_trips_through_text() {
        let m: MacAddr = "aa:bb:cc:dd:ee:01".parse().expect("valid");
        assert_eq!(m.octets(), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:01");
        assert_eq!("aa-bb-cc-dd-ee-01".parse::<MacAddr>().expect("dashes"), m);
        assert!(!m.is_group());
        assert!(MacAddr::BROADCAST.is_group());
    }

    #[test]
    fn mac_rejects_wrong_arity_and_digits() {
        for bad in [
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:01:02",
            "zz:bb:cc:dd:ee:01",
            "",
        ] {
            assert!(bad.parse::<MacAddr>().is_err(), "{bad:?} must not parse");
        }
    }

    #[test]
    fn integers_accept_decimal_and_hex_and_reject_overflow() {
        assert_eq!(TypedVal::parse(ValKind::U16, "31"), Ok(TypedVal::U16(31)));
        assert_eq!(TypedVal::parse(ValKind::U16, "0x1f"), Ok(TypedVal::U16(31)));
        assert_eq!(
            TypedVal::parse(ValKind::U8, "256"),
            Err(ValueError::Malformed {
                kind: ValKind::U8,
                text: "256".into()
            })
        );
    }

    #[test]
    fn kind_mismatch_is_reported_not_coerced() {
        assert_eq!(
            TypedVal::U8(1).require(ValKind::U16),
            Err(ValueError::Mismatched {
                expected: ValKind::U16,
                got: ValKind::U8
            })
        );
    }
}
