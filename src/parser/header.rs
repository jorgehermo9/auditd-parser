use nom::bytes::complete::{tag, take, take_while1};
use nom::character::complete::u64 as parse_u64;
use nom::sequence::{delimited, preceded, separated_pair};
use nom::{AsChar, IResult, Parser};

#[derive(Debug)]
pub struct InnerHeader {
    pub record_type: String,
    pub audit_msg: InnerAuditMsg,
}

#[derive(Debug)]
pub struct InnerAuditMsg {
    pub timestamp: u64,
    pub uid: u64,
}

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
        .map(|(timestamp, uid)| InnerAuditMsg { timestamp, uid })
        .parse(input)
}

/// Parses the `msg=audit(1234.567:89): ` part of the message.
fn parse_audit_msg(input: &str) -> IResult<&str, InnerAuditMsg> {
    delimited(tag("msg="), parse_audit_msg_value, tag(": ")).parse(input)
}

/// Parses the header of the record, which contains the record type and the audit message part.
///
/// Example: `type=USER_ACCT msg=audit(1725039526.208:52): `
pub fn parse_header(input: &str) -> IResult<&str, InnerHeader> {
    separated_pair(parse_record_type, tag(" "), parse_audit_msg)
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
    #[case::trailing_space("type=USER_ACCT ", "USER_ACCT")]
    #[case::numeric("type=123", "123")]
    #[case::special_chars("type=?USER_ACCT!", "?USER_ACCT!")]
    fn test_parse_record_type(#[case] input: &str, #[case] expected: &str) {
        let (_, result) = parse_record_type(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::no_key("USER_ACCT")]
    #[case::no_value("type=")]
    #[case::wrong_key("wrong_key=USER_ACCT")]
    #[case::empty_input("")]
    fn test_parse_record_type_fails(#[case] input: &str) {
        assert!(parse_record_type(input).is_err());
    }

    #[rstest]
    #[case::regular("123", 123)]
    #[case::leading_zeroes("001", 1)]
    #[case::max_value("999", 999)]
    #[case::min_value("000", 0)]
    fn test_parse_timestamp_milliseconds(#[case] input: &str, #[case] expected: u64) {
        let (_, result) = parse_timestamp_milliseconds(input).unwrap();
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
    #[case::regular("123.456", 123456)]
    #[case::leading_zeroes("001.234", 1234)]
    #[case::zero_seconds("000.123", 123)]
    fn test_parse_timestamp(#[case] input: &str, #[case] expected: u64) {
        let (_, result) = parse_timestamp(input).unwrap();
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::non_numeric("abc")]
    #[case::missing_dot("123")]
    #[case::two_consecutive_dots("123..456")]
    #[case::empty_input("")]
    fn test_parse_timestamp_fails(#[case] input: &str) {
        assert!(parse_timestamp(input).is_err());
    }
}
