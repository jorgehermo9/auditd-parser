use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use bytes::{Buf, Bytes};

const AF_LOCAL: u16 = 1;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
// TODO: print AF_NETLINK like `ss -f netlink` does
const AF_NETLINK: u16 = 16;

#[derive(Debug, PartialEq)]
pub enum SocketAddr {
    Local(SocketAddrLocal),
    Inet(SocketAddrV4),
    Inet6(SocketAddrV6),
    Netlink(SocketAddrNetlink),
}

impl SocketAddr {
    pub fn family(&self) -> &'static str {
        match self {
            Self::Local(_) => "AF_LOCAL",
            Self::Inet(_) => "AF_INET",
            Self::Inet6(_) => "AF_INET6",
            Self::Netlink(_) => "AF_NETLINK",
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct SocketAddrLocal {
    pub path: String,
}

#[derive(Debug, PartialEq)]
pub struct SocketAddrNetlink {
    pub port_id: u32,
    pub groups: u32,
}

// We will parse the `sockaddr` struct memory layout.
// This parsing will be very sensitive of the host machine's endianness.
// Therefore, we will assume that the machine's endianness is little-endian (it is the most common one)
// Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/linux/socket.h#L35
pub fn parse_sockaddr(mut bytes: Bytes) -> Option<SocketAddr> {
    if bytes.remaining() < 2 {
        return None;
    }

    // The first field is the `sa_family` field, of type `sa_family_t`,
    // which is defined as an `unsigned short` in the kernel (https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/socket.h#L10)
    // We will assume that `unsigned short` is 16-bit in size (it is the most common)
    // Also, the endianness of this field is not defined in sourcecode,
    // so we will assume that it is little-endian.
    // Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/linux/socket.h#L29
    let family = bytes.get_u16_le();

    match family {
        AF_LOCAL => Some(SocketAddr::Local(parse_af_local(bytes))),
        AF_INET => parse_af_inet(bytes).map(SocketAddr::Inet),
        AF_INET6 => parse_af_inet6(bytes).map(SocketAddr::Inet6),
        // TODO: output None or something like `saddr=unknown family(0)` as auparse does..
        _ => None,
    }
}

// Parses a `sockaddr_un` struct memory layout.
// Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/un.h#L9
fn parse_af_local(bytes: Bytes) -> SocketAddrLocal {
    // The `sun_path` field is a char array. Strings in C are null-terminated,
    // so we will read bytes until we find a null byte.
    let path = bytes
        .into_iter()
        .take_while(|&b| b != 0)
        .map(|b| b as char)
        .collect::<String>();

    SocketAddrLocal { path }
}

// Parses a `sockaddr_in` struct memory layout.
// Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/in.h#L260
fn parse_af_inet(mut bytes: Bytes) -> Option<SocketAddrV4> {
    if bytes.remaining() < 6 {
        return None;
    }

    // The next field is the `sin_port` field, of type `__be16`,
    // which is a 16-bit integer with a specified endianness (big-endian)
    // as network byte order is an standard in internet-related protocols.
    // Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/in.h#L262
    let port = bytes.get_u16();

    // Then, the `sin_addr` field, of type `struct in_addr`
    // In the `in_addr` struct, the `s_addr` field is of type `__be32`,
    // which is a 32-bit big-endian integer.
    // Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/in.h#L97
    let address = Ipv4Addr::from_bits(bytes.get_u32());

    Some(SocketAddrV4::new(address, port))
}

// Parses a `sockaddr_in6` struct memory layout.
// Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/in6.h#L50
fn parse_af_inet6(mut bytes: Bytes) -> Option<SocketAddrV6> {
    if bytes.remaining() < 26 {
        return None;
    }

    // The `sin6_port` field is a 16-bit big-endian integer
    let port = bytes.get_u16();

    // The `sin6_flowinfo` field is a 32-bit big-endian integer
    let flowinfo = bytes.get_u32();

    // The `sin6_addr` field is of type `struct in6_addr`.
    // That struct containts a 16-byte array `u6_addr8`, which is the IPv6 address.
    // Also, if the macro `__UAPI_DEF_IN6_ADDR_ALT` is set, that struct  contains
    // another two fields that span two 128-bit fields (total of 256 bits)
    // We will assume (at least for now) that the macro is not set and
    // the `sin_addr` struct is 128 bits long.
    let address = Ipv6Addr::from_bits(bytes.get_u128());

    // Lastly, after the `sin6_addr` field, there is the `sin6_scope_id` field,
    // which is a 32-bit integer with no specified endianness, so we assume it is
    // little-endian. We have to be very careful with this field, as it comes after `sin6_addr` and
    // we assume that `__UAPI_DEF_IN6_ADDR_ALT`. If that macro is set, the scope id we are reading
    // here will be incorrect (as we would have to skip 256 bits from the input to reach this field)
    let scope_id = bytes.get_u32_le();

    Some(SocketAddrV6::new(address, port, flowinfo, scope_id))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;

    use super::*;

    impl FromStr for SocketAddrLocal {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(SocketAddrLocal {
                path: s.to_string(),
            })
        }
    }

    impl FromStr for SocketAddr {
        type Err = ();

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            if let Ok(address) = s.parse::<SocketAddrV4>() {
                return Ok(SocketAddr::Inet(address));
            }

            if let Ok(address) = s.parse::<SocketAddrV6>() {
                return Ok(SocketAddr::Inet6(address));
            }

            if let Ok(address) = s.parse::<SocketAddrLocal>() {
                return Ok(SocketAddr::Local(address));
            }

            Err(())
        }
    }

    #[rstest]
    #[case::af_local("01002F7661722F72756E2F6E7363642F736F636B6574", "/var/run/nscd/socket")]
    #[case::af_inet("02000050A9FEA9FE", "169.254.169.254:80")]
    #[case::af_inet6(
        "0A0000160000000020010DC8E0040001000000000000F00A00000000",
        "[2001:dc8:e004:1::f00a]:22"
    )]
    fn test_parse_sockaddr(#[case] input: &str, #[case] expected: SocketAddr) {
        let bytes = Bytes::from(hex::decode(input).unwrap());
        let result = parse_sockaddr(bytes).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_sockaddr_fails_unknown_famly() {
        let input = "FFFF0050A9FEA9FE";
        let bytes = Bytes::from(hex::decode(input).unwrap());
        let result = parse_sockaddr(bytes);
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_sockaddr_fails_not_enough_bytes() {
        let bytes = Bytes::from(vec![0x12u8]);
        let result = parse_sockaddr(bytes);
        assert_eq!(result, None);
    }

    #[rstest]
    #[case::non_null_terminated("2F7661722F72756E2F6E7363642F736F636B6574", "/var/run/nscd/socket")]
    #[case::null_terminated("2F7661722F72756E2F6E7363642F736F636B657400", "/var/run/nscd/socket")]
    #[case::trailing_data(
        "2F7661722F72756E2F6E7363642F736F636B65740000603B7B47FC7F0000303C7B47FC7F0000020000000000000014000000160001030800000000000000C03B7B47FC7F0000103B7B47FC7F00002000000000000000303C7B47FC7F0000C0FB39861C7F0000787F2F861C7F",
        "/var/run/nscd/socket"
    )]
    #[case::empty_path("00", "")]
    #[case::empty_input("", "")]
    fn test_parse_af_local(#[case] input: &str, #[case] expected: SocketAddrLocal) {
        let bytes = Bytes::from(hex::decode(input).unwrap());

        let result = parse_af_local(bytes);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::simple("0050A9FEA9FE", "169.254.169.254:80")]
    #[case::trailing_data("0050A9FEA9FE0000000000000000", "169.254.169.254:80")]
    #[case::localhost("00507F000001", "127.0.0.1:80")]
    #[case::all_zeros("000000000000", "0.0.0.0:0")]
    #[case::all_ones("FFFFFFFFFFFF", "255.255.255.255:65535")]
    fn test_parse_af_inet(#[case] input: &str, #[case] expected: SocketAddrV4) {
        let bytes = Bytes::from(hex::decode(input).unwrap());

        let result = parse_af_inet(bytes).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_af_inet_fails_not_enough_bytes() {
        let bytes = Bytes::from(vec![0x12u8, 0x34u8]);
        let result = parse_af_inet(bytes);
        assert_eq!(result, None);
    }

    #[rstest]
    #[case::simple(
        "00160000000020010DC8E0040001000000000000F00A00000000",
        "[2001:dc8:e004:1::f00a]:22"
    )]
    #[case::with_flow_info(
        "00160000000120010DC8E0040001000000000000F00A00000000",
        "[2001:dc8:e004:1::f00a]:22"
    )]
    #[case::with_scope_id(
        "00160000000020010DC8E0040001000000000000F00A01000000",
        "[2001:dc8:e004:1::f00a%1]:22"
    )]
    #[case::localhost("0016000000000000000000000000000000000000000100000000", "[::1]:22")]
    #[case::all_zeros_with_port("0016000000000000000000000000000000000000000000000000", "[::]:22")]
    #[case::all_zeros("0000000000000000000000000000000000000000000000000000", "[::]:0")]
    #[case::all_ones(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535"
    )]
    fn test_parse_af_inet6(#[case] input: &str, #[case] expected: SocketAddrV6) {
        let bytes = Bytes::from(hex::decode(input).unwrap());
        let result = parse_af_inet6(bytes).unwrap();
        // We assert the `to_string()` representation because the `flowinfo` field is not used
        // in the `FromStr` implementation of `SocketAddrV6` and therefore the expected SocketAddrV6
        // would have a `flowinfo` value of 0.
        // `assert_eq!(result, expected);` would fail because of that.
        assert_eq!(result.to_string(), expected.to_string());
    }

    #[test]
    fn test_parse_af_inet6_fails_not_enough_bytes() {
        let bytes = Bytes::from(vec![0x12u8, 0x34u8]);
        let result = parse_af_inet6(bytes);
        assert_eq!(result, None);
    }
}
