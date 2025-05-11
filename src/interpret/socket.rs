// 02000050A9FEA9FE0000000000000000
//
//
//

use std::net::{Ipv4Addr, SocketAddrV4};

use bytes::{Buf, Bytes};

const AF_LOCAL: u16 = 1;
const AF_INET: u16 = 2;

// We will parse the `sockaddr` struct memory layout.
// This parsing will be very sensitive of the host machine's endianness.
// Therefore, we will assume that the machine's endianness is little-endian (it is the most common one)
// Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/linux/socket.h#L35
pub fn parse_sockaddr(mut bytes: Bytes) -> Option<String> {
    // The first field is the `sa_family` field, of type `sa_family_t`,
    // which is defined as an `unsigned short` in the kernel (https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/socket.h#L10)
    // We will assume that `unsigned short` is 16-bit in size (it is the most common)
    // Also, the endianness of this field is not defined in sourcecode,
    // so we will assume that it is little-endian.
    // Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/linux/socket.h#L29

    let family = bytes.get_u16_le();

    match family {
        AF_INET => parse_af_inet(bytes),
        // output None or something like `saddr=unknown family(0)` as auparse does..
        AF_LOCAL => Some(parse_af_local(bytes)),
        _ => None,
    }
}

// Parses a `sockaddr_in` struct memory layout.
// Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/in.h#L260
fn parse_af_inet(mut bytes: Bytes) -> Option<String> {
    // Ensure that there are at lesat 6 bytes remaining in the buffer
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

    let socket_address = SocketAddrV4::new(address, port);
    Some(socket_address.to_string())
}

// Parses a `sockaddr_un` struct memory layout.
// Ref: https://github.com/torvalds/linux/blob/cd802e7e5f1e77ae68cd98653fb70a97189eb937/include/uapi/linux/un.h#L9
fn parse_af_local(bytes: Bytes) -> String {
    // The `sun_path` field is a char array. Strings in C are null-terminated,
    // so we will read bytes until we find a null byte.
    bytes
        .into_iter()
        .take_while(|&b| b != 0)
        .map(|b| b as char)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::af_inet("02000050A9FEA9FE", "169.254.169.254:80")]
    fn test_parse_sockaddr(#[case] input: &str, #[case] expected: &str) {
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

    #[rstest]
    #[case::simple("0050A9FEA9FE", "169.254.169.254:80")]
    #[case::trailing_data("0050A9FEA9FE0000000000000000", "169.254.169.254:80")]
    #[case::localhost("00507F000001", "127.0.0.1:80")]
    #[case::all_zeros("000000000000", "0.0.0.0:0")]
    #[case::all_ones("FFFFFFFFFFFF", "255.255.255.255:65535")]
    fn test_parse_af_inet(#[case] input: &str, #[case] expected: &str) {
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
    #[case::non_null_terminated("2F7661722F72756E2F6E7363642F736F636B6574", "/var/run/nscd/socket")]
    #[case::null_terminated("2F7661722F72756E2F6E7363642F736F636B657400", "/var/run/nscd/socket")]
    #[case::trailing_data(
        "2F7661722F72756E2F6E7363642F736F636B65740000603B7B47FC7F0000303C7B47FC7F0000020000000000000014000000160001030800000000000000C03B7B47FC7F0000103B7B47FC7F00002000000000000000303C7B47FC7F0000C0FB39861C7F0000787F2F861C7F",
        "/var/run/nscd/socket"
    )]
    #[case::empty_path("00", "")]
    #[case::empty_input("", "")]
    fn test_parse_af_local(#[case] input: &str, #[case] expected: &str) {
        let bytes = Bytes::from(hex::decode(input).unwrap());
        let result = parse_af_local(bytes);
        assert_eq!(result, expected);
    }
}
