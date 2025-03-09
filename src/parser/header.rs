use nom::bytes::complete::{tag, take, take_until1};
use nom::character::complete::u64 as parse_u64;
use nom::sequence::{delimited, separated_pair};
use nom::{IResult, Parser};

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
    delimited(tag("type="), take_until1(" "), tag(" "))
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
    (parse_record_type, parse_audit_msg)
        .map(|(record_type, audit_msg)| InnerHeader {
            record_type,
            audit_msg,
        })
        .parse(input)
}
