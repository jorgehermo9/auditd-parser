use nom::bytes::complete::{tag, take, take_while1};
use nom::character::complete::{char, u64 as parse_u64};
use nom::sequence::{delimited, preceded, separated_pair};
use nom::{AsChar, IResult, Parser};

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InnerHeader {
    pub record_type: String,
    pub audit_msg: InnerAuditMsg,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct InnerAuditMsg {
    pub timestamp: u64,
    pub id: u64,
}

// TODO: reorder these functions so we go from high-level to low-level

fn parse_record_type(input: &str) -> IResult<&str, String> {
    preceded(tag("type="), take_while1(|c: char| !c.is_space()))
        .map(ToString::to_string)
        .parse(input)
}

/// Parses the timestamp decimal part as milliseconds. It is important
/// to note that just 3 decimal digits are su
fn parse_timestamp_milliseconds(input: &str) -> IResult<&str, u64> {
    take(3usize).and_then(parse_u64).parse(input)
}

/// Parses a timestamp in `1234.567` format, where the whole part
/// are seconds and the decimal part are milliseconds.
fn parse_timestamp(input: &str) -> IResult<&str, u64> {
    separated_pair(parse_u64, tag("."), parse_timestamp_milliseconds)
        .map(|(seconds, milliseconds)| seconds * 1000 + milliseconds)
        .parse(input)
}

/// Parses a timestamp and a UID in `1234.567:89` format.
fn parse_timestamp_and_uid(input: &str) -> IResult<&str, (u64, u64)> {
    separated_pair(parse_timestamp, tag(":"), parse_u64).parse(input)
}

/// Parses the `audit(1234.567:89)` part of the message.
fn parse_audit_msg_value(input: &str) -> IResult<&str, InnerAuditMsg> {
    delimited(tag("audit("), parse_timestamp_and_uid, tag(")"))
        .map(|(timestamp, uid)| InnerAuditMsg { timestamp, id: uid })
        .parse(input)
}

/// Parses the `msg=audit(1234.567:89): ` part of the message.
fn parse_audit_msg(input: &str) -> IResult<&str, InnerAuditMsg> {
    // TODO: allow for ":" and ": "? (with and without trailing space)
    delimited(tag("msg="), parse_audit_msg_value, tag(": ")).parse(input)
}

// TODO: parse `node` field of auditd records
/// Parses the header of the record, which contains the record type and the audit message part.
///
/// Example: `type=USER_ACCT msg=audit(1725039526.208:52): `
pub fn parse_header(input: &str) -> IResult<&str, InnerHeader> {
    separated_pair(parse_record_type, char(' '), parse_audit_msg)
        .map(|(record_type, audit_msg)| InnerHeader {
            record_type,
            audit_msg,
        })
        .parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::regular("type=USER_ACCT", "USER_ACCT")]
    #[case::quoted("type=\"USER_ACCT\"", "\"USER_ACCT\"")]
    #[case::numeric("type=123", "123")]
    #[case::special_chars("type=?USER_ACCT!", "?USER_ACCT!")]
    fn test_parse_record_type(#[case] input: &str, #[case] expected: &str) {
        let (remaining, result) = parse_record_type(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::without_key("USER_ACCT")]
    #[case::without_value("type=")]
    #[case::wrong_key("wrong_key=USER_ACCT")]
    #[case::empty_input("")]
    fn test_parse_record_type_fails(#[case] input: &str) {
        // TODO: migrate all those assert is_err to `assert_matches` once it stabilizes
        // https://github.com/rust-lang/rust/issues/82775
        assert!(parse_record_type(input).is_err());
    }

    #[rstest]
    #[case::regular("123", 123)]
    #[case::leading_zeroes("001", 1)]
    #[case::max_value("999", 999)]
    #[case::min_value("000", 0)]
    fn test_parse_timestamp_milliseconds(#[case] input: &str, #[case] expected: u64) {
        let (remaining, result) = parse_timestamp_milliseconds(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::non_numeric("abc")]
    #[case::less_than_3_digits("12")]
    #[case::empty_input("")]
    fn test_parse_timestamp_milliseconds_fail(#[case] input: &str) {
        assert!(parse_timestamp_milliseconds(input).is_err());
    }

    #[rstest]
    #[case::regular("123.456", 123_456)]
    #[case::leading_zeroes("001.234", 1234)]
    #[case::zero_seconds("000.123", 123)]
    #[case::zero_milliseconds("123.000", 123_000)]
    #[case::min_value("000.000", 0)]
    fn test_parse_timestamp(#[case] input: &str, #[case] expected: u64) {
        let (remaining, result) = parse_timestamp(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::with_invalid_seconds("abc.123")]
    #[case::with_invalid_milliseconds("123.abc")]
    #[case::without_milliseconds("123")]
    #[case::two_consecutive_dots("123..456")]
    #[case::non_numeric("abc")]
    #[case::empty_input("")]
    fn test_parse_timestamp_fails(#[case] input: &str) {
        assert!(parse_timestamp(input).is_err());
    }

    #[rstest]
    #[case::regular("123.456:789", (123_456, 789))]
    #[case::zero_milliseconds("123.000:789", (123_000, 789))]
    fn test_parse_timestamp_and_uid(#[case] input: &str, #[case] expected: (u64, u64)) {
        let (remaining, result) = parse_timestamp_and_uid(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::with_invalid_timestamp("abc:789")]
    #[case::with_invalid_id("123:def")]
    #[case::without_colon_separator("123.456")]
    #[case::empty_input("")]
    fn test_parse_timestamp_and_uid_fails(#[case] input: &str) {
        assert!(parse_timestamp_and_uid(input).is_err());
    }

    #[rstest]
    #[case::regular("audit(123.456:789)", InnerAuditMsg { timestamp: 123_456, id: 789 })]
    fn test_parse_audit_msg_value(#[case] input: &str, #[case] expected: InnerAuditMsg) {
        let (remaining, result) = parse_audit_msg_value(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::with_invalid_timestamp_and_uid("audit(123:abc)")]
    #[case::without_delimiters("123.456:789")]
    #[case::without_suffix("audit(123.456:789")]
    #[case::without_prefix("123.456:789)")]
    #[case::non_numeric("abcdef")]
    #[case::empty_input("")]
    fn test_parse_audit_msg_value_fails(#[case] input: &str) {
        assert!(parse_audit_msg_value(input).is_err());
    }

    #[rstest]
    #[case::regular("msg=audit(123.456:789): ", InnerAuditMsg { timestamp: 123_456, id: 789 })]
    fn test_parse_audit_msg(#[case] input: &str, #[case] expected: InnerAuditMsg) {
        let (remaining, result) = parse_audit_msg(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::with_invalid_audit_msg_value("msg=123.456:789): ")]
    #[case::without_prefix_key("audit(123.456:789): ")]
    #[case::without_suffix_trailing_space("msg=audit(123.456:789):")]
    #[case::without_suffix_semicolon("msg=audit(123.456:789)")]
    #[case::without_audit_msg_value("msg=")]
    #[case::without_prefix_and_suffix("audit(123.456:789)")]
    #[case::empty_input("")]
    fn test_parse_audit_msg_fails(#[case] input: &str) {
        assert!(parse_audit_msg(input).is_err());
    }

    #[rstest]
    #[case::regular("type=USER_ACCT msg=audit(123.456:789): ", InnerHeader { record_type: "USER_ACCT".to_string(), audit_msg: InnerAuditMsg { timestamp: 123_456, id: 789 } })]
    fn test_parse_header(#[case] input: &str, #[case] expected: InnerHeader) {
        let (remaining, result) = parse_header(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::with_invalid_record_type("type= msg=audit(123.456:789): ")]
    #[case::with_invalid_audit_msg("type=USER_ACCT msg=123.456:78): ")]
    #[case::without_record_type("msg=audit(123.456:789): ")]
    #[case::without_audit_msg("type=USER_ACCT")]
    #[case::without_space_separator("type=USER_ACCTmsg=audit(123.456:789): ")]
    #[case::with_two_spaces_separator("type=USER_ACCT  msg=audit(123.456:789): ")]
    #[case::with_non_space_separator("type=USER_ACCT\tmsg=audit(123.456:789): ")]
    #[case::empty_input("")]
    fn test_parse_header_fails(#[case] input: &str) {
        assert!(parse_header(input).is_err());
    }
}
