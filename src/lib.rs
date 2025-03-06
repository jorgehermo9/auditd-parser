use std::{collections::HashMap, str::FromStr};

use nom::bytes::take_until1;
use nom::character::complete::u64 as parse_u64;
use nom::combinator::map;
use nom::sequence::delimited;
use nom::{IResult, Parser, bytes::complete::tag, sequence::separated_pair};

use nom::character::complete::char;

// TODO: implement an interpret to convert hexadecimal values into human-readable
// format, as `ausearch --interpret` does
// Example the `arch` field in https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files#sec-Understanding_Audit_Log_Files
// Create an InterpretedAuditdRecord that transforms an AuditdRecord into a human-readable format

#[derive(Debug)]
struct AuditdRecord {
    record_type: String,
    // TODO: u64 or chrono::DateTime<chrono::Utc>?
    /// Unix timestamp in milliseconds
    timestamp: u64,

    // TODO: u64 or u32?
    /// Record unique identifier
    uid: u64,

    // TODO: create a FieldValue type and store it instead of Strings.
    // We could have hexadecimal, integer, string, and key-value types there
    fields: HashMap<String, String>,
}

#[derive(Debug)]
struct InnerHeader {
    record_type: String,
    msg: InnerAuditMsg,
}

#[derive(Debug)]
struct InnerAuditMsg {
    timestamp: u64,
    uid: u64,
}

fn parse_record_type(input: &str) -> IResult<&str, String> {
    delimited(tag("type="), take_until1(" "), tag(" "))
        .map(ToString::to_string)
        .parse(input)
}

/// Parses a timestamp in `1234.567` format, where the whole part
/// are seconds and the decimal part are milliseconds.
fn parse_timestamp(input: &str) -> IResult<&str, u64> {
    separated_pair(parse_u64, tag("."), parse_u64)
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

// TODO: return a Header Struct instead of a tuple
fn parse_header(s: &str) -> IResult<&str, InnerHeader> {
    (parse_record_type, parse_audit_msg)
        .map(|(record_type, msg)| InnerHeader { record_type, msg })
        .parse(s)
}

fn parse_body(s: &str) -> IResult<&str, &str> {
    return Ok(("", s));
}

fn parse_record(s: &str) -> IResult<&str, AuditdRecord> {
    let (_, (header, body)) = (parse_header, parse_body).parse(s)?;
    dbg!(header, body);
    todo!()
}

impl FromStr for AuditdRecord {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_record(s).unwrap();
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let line = r#"type=USER_ACCT msg=audit(1725039526.208:52): pid=580903 uid=1000 auid=1000 ses=2 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="jorge" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'UID="jorge" AUID="jorge""#;
        dbg!(line.parse::<AuditdRecord>());
    }
}
