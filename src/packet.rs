//! ip packet validation.
//!
//! checks the ip version, header length and total length before a packet is
//! forwarded. bad packets are dropped.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// smallest ipv4 header, no options.
pub const IPV4_MIN_HEADER_LEN: usize = 20;

/// ipv6 header size, fixed.
pub const IPV6_HEADER_LEN: usize = 40;

/// packet validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// not enough bytes for a header.
    TooShort {
        /// bytes received.
        len: usize,
    },
    /// ip version nibble is not 4 or 6.
    UnsupportedVersion(u8),
    /// ipv4 ihl below 5, or header longer than the packet.
    InvalidIpv4HeaderLen {
        /// ipv4 header length in 32-bit words.
        ihl: u8,
        /// bytes received.
        len: usize,
    },
    /// total length field does not match the packet size.
    LengthMismatch {
        /// length from the header.
        declared: usize,
        /// bytes received.
        actual: usize,
    },
}

/// check a slice is a valid ipv4 or ipv6 packet.
pub fn validate(packet: &[u8]) -> Result<(), PacketError> {
    let Some(&first) = packet.first() else {
        return Err(PacketError::TooShort { len: 0 });
    };

    match first >> 4 {
        4 => validate_ipv4(packet),
        6 => validate_ipv6(packet),
        version => Err(PacketError::UnsupportedVersion(version)),
    }
}

fn validate_ipv4(packet: &[u8]) -> Result<(), PacketError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(PacketError::TooShort { len: packet.len() });
    }

    let ihl = packet[0] & 0x0f;
    let header_len = usize::from(ihl) * 4;
    if ihl < 5 || header_len > packet.len() {
        return Err(PacketError::InvalidIpv4HeaderLen {
            ihl,
            len: packet.len(),
        });
    }

    let declared = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if declared != packet.len() {
        return Err(PacketError::LengthMismatch {
            declared,
            actual: packet.len(),
        });
    }

    Ok(())
}

fn validate_ipv6(packet: &[u8]) -> Result<(), PacketError> {
    if packet.len() < IPV6_HEADER_LEN {
        return Err(PacketError::TooShort { len: packet.len() });
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let declared = IPV6_HEADER_LEN + payload_len;
    if declared != packet.len() {
        return Err(PacketError::LengthMismatch {
            declared,
            actual: packet.len(),
        });
    }

    Ok(())
}

/// the destination address of a valid packet, v4 or v6.
///
/// returns `None` for anything `validate` would reject. callers that already
/// validated can treat this as infallible.
pub fn destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|first| first >> 4)? {
        4 if packet.len() >= IPV4_MIN_HEADER_LEN => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= IPV6_HEADER_LEN => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// the ipv4 ttl or ipv6 hop limit of a valid packet.
pub fn hop_limit(packet: &[u8]) -> Option<u8> {
    match packet.first().map(|first| first >> 4)? {
        4 if packet.len() >= IPV4_MIN_HEADER_LEN => Some(packet[8]),
        6 if packet.len() >= IPV6_HEADER_LEN => Some(packet[7]),
        _ => None,
    }
}

/// decrement the ttl or hop limit in place, fixing the ipv4 header checksum.
///
/// returns false when the hop limit was already 1 (or the packet isn't a
/// well-formed v4/v6 packet), meaning the packet must be dropped rather than
/// forwarded.
pub fn decrement_hop_limit(packet: &mut [u8]) -> bool {
    match packet.first().map(|first| first >> 4) {
        Some(4) if packet.len() >= IPV4_MIN_HEADER_LEN => {
            let ihl = packet[0] & 0x0f;
            let header_len = usize::from(ihl) * 4;
            // defence in depth: a caller could hand us a packet that was not run
            // through `validate`, so never index past the buffer while fixing the
            // header checksum.
            if ihl < 5 || header_len > packet.len() {
                return false;
            }
            if packet[8] <= 1 {
                return false;
            }
            packet[8] -= 1;
            packet[10] = 0;
            packet[11] = 0;
            let checksum = ipv4_checksum(&packet[..header_len]);
            packet[10..12].copy_from_slice(&checksum.to_be_bytes());
            true
        }
        Some(6) if packet.len() >= IPV6_HEADER_LEN => {
            if packet[7] <= 1 {
                return false;
            }
            packet[7] -= 1;
            true
        }
        _ => false,
    }
}

/// internet checksum over an ipv4 header, which must have a zeroed checksum field.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = match chunk {
            [high, low] => u16::from_be_bytes([*high, *low]),
            [high] => u16::from(*high) << 8,
            _ => 0,
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => write!(f, "packet too short: {len} bytes"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported ip version: {version}")
            }
            Self::InvalidIpv4HeaderLen { ihl, len } => {
                write!(
                    f,
                    "invalid ipv4 header length: ihl {ihl} with {len} bytes present"
                )
            }
            Self::LengthMismatch { declared, actual } => write!(
                f,
                "packet length mismatch: header says {declared} bytes but {actual} present"
            ),
        }
    }
}

impl Error for PacketError {}

#[cfg(test)]
mod tests {
    use super::*;

    // a valid ipv4 packet of `len` bytes (len >= 20), ihl 5, total length set.
    fn ipv4(len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[9] = 17; // udp
        packet
    }

    fn ipv6(payload_len: usize) -> Vec<u8> {
        let total = IPV6_HEADER_LEN + payload_len;
        let mut packet = vec![0u8; total];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = 17; // next header: udp
        packet
    }

    #[test]
    fn accepts_a_valid_ipv4_packet() {
        assert_eq!(validate(&ipv4(20)), Ok(()));
        assert_eq!(validate(&ipv4(40)), Ok(()));
    }

    #[test]
    fn accepts_a_valid_ipv4_packet_with_options() {
        let mut packet = ipv4(24);
        packet[0] = 0x46; // ihl 6 -> 24 byte header
        assert_eq!(validate(&packet), Ok(()));
    }

    #[test]
    fn rejects_empty_and_short_packets() {
        assert_eq!(validate(&[]), Err(PacketError::TooShort { len: 0 }));
        assert_eq!(validate(&ipv4(19)), Err(PacketError::TooShort { len: 19 }));
    }

    #[test]
    fn rejects_unknown_version() {
        assert_eq!(
            validate(&[0x50, 0, 0, 0, 0]),
            Err(PacketError::UnsupportedVersion(5))
        );
    }

    #[test]
    fn rejects_bad_ipv4_header_len() {
        let mut too_small = ipv4(20);
        too_small[0] = 0x44; // ihl 4
        assert_eq!(
            validate(&too_small),
            Err(PacketError::InvalidIpv4HeaderLen { ihl: 4, len: 20 })
        );

        let mut past_end = ipv4(20);
        past_end[0] = 0x4f; // ihl 15 -> 60 bytes, more than present
        assert_eq!(
            validate(&past_end),
            Err(PacketError::InvalidIpv4HeaderLen { ihl: 15, len: 20 })
        );
    }

    #[test]
    fn rejects_ipv4_length_mismatch() {
        let mut packet = ipv4(20);
        packet[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            validate(&packet),
            Err(PacketError::LengthMismatch {
                declared: 100,
                actual: 20
            })
        );
    }

    #[test]
    fn accepts_a_valid_ipv6_packet() {
        assert_eq!(validate(&ipv6(0)), Ok(()));
        assert_eq!(validate(&ipv6(16)), Ok(()));
    }

    #[test]
    fn rejects_short_ipv6_packet() {
        assert_eq!(
            validate(&ipv6(0)[..IPV6_HEADER_LEN - 1]),
            Err(PacketError::TooShort {
                len: IPV6_HEADER_LEN - 1
            })
        );
    }

    #[test]
    fn rejects_ipv6_length_mismatch() {
        let mut packet = ipv6(8);
        packet[4..6].copy_from_slice(&64u16.to_be_bytes());
        assert_eq!(
            validate(&packet),
            Err(PacketError::LengthMismatch {
                declared: IPV6_HEADER_LEN + 64,
                actual: IPV6_HEADER_LEN + 8
            })
        );
    }

    #[test]
    fn reads_ipv4_destination_and_hop_limit() {
        let mut packet = ipv4(20);
        packet[8] = 64;
        packet[16..20].copy_from_slice(&[10, 0, 0, 3]);
        assert_eq!(destination(&packet), Some("10.0.0.3".parse().unwrap()));
        assert_eq!(hop_limit(&packet), Some(64));
    }

    #[test]
    fn reads_ipv6_destination_and_hop_limit() {
        let mut packet = ipv6(0);
        packet[7] = 32;
        packet[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(destination(&packet), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(hop_limit(&packet), Some(32));
    }

    #[test]
    fn destination_and_hop_limit_reject_bad_packets() {
        assert_eq!(destination(&[]), None);
        assert_eq!(destination(&[0x30, 0, 0]), None);
        assert_eq!(hop_limit(&ipv4(19)), None);
    }

    #[test]
    fn decrementing_ipv4_ttl_fixes_the_checksum() {
        let mut packet = ipv4(20);
        packet[8] = 10;
        assert!(decrement_hop_limit(&mut packet));
        assert_eq!(hop_limit(&packet), Some(9));

        // a correct checksum makes the ones-complement sum over the header 0xffff
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let mut sum = 0u32;
        for chunk in packet[..header_len].chunks(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xffff);
    }

    #[test]
    fn decrementing_reports_expiry() {
        let mut v4 = ipv4(20);
        v4[8] = 1;
        assert!(!decrement_hop_limit(&mut v4));
        assert_eq!(hop_limit(&v4), Some(1), "expired packet is left untouched");

        let mut v6 = ipv6(0);
        v6[7] = 1;
        assert!(!decrement_hop_limit(&mut v6));
        assert_eq!(hop_limit(&v6), Some(1));

        let mut zero = ipv4(20);
        zero[8] = 0;
        assert!(!decrement_hop_limit(&mut zero));
    }

    #[test]
    fn decrementing_ipv6_hop_limit() {
        let mut packet = ipv6(0);
        packet[7] = 5;
        assert!(decrement_hop_limit(&mut packet));
        assert_eq!(hop_limit(&packet), Some(4));
    }

    #[test]
    fn decrementing_rejects_a_malformed_header_len_without_panicking() {
        // ihl 15 means a 60 byte header but only 20 bytes are present. a caller
        // that skipped validation must get `false`, not a slice-index panic.
        let mut packet = ipv4(20);
        packet[0] = 0x4f;
        packet[8] = 64;
        assert!(!decrement_hop_limit(&mut packet));

        // and an ihl below the minimum.
        let mut short = ipv4(20);
        short[0] = 0x44;
        short[8] = 64;
        assert!(!decrement_hop_limit(&mut short));
    }
}
