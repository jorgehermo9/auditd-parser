use std::{collections::HashMap, str::FromStr};

use crate::utils::consume_all;
use nom::branch::alt;
use nom::bytes::complete::{tag, take, take_until1, take_while1};
use nom::character::complete::{char, space1, u64 as parse_u64};
use nom::combinator::all_consuming;
use nom::multi::separated_list1;
use nom::sequence::{delimited, separated_pair};
use nom::{AsChar, Finish};
use nom::{IResult, Parser};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod utils;

const ENRICHMENT_SEPARATOR: char = '\x1d';

// TODO: implement an interpret to convert hexadecimal values into human-readable
// format, as `ausearch --interpret` does
// Example the `arch` field in https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files#sec-Understanding_Audit_Log_Files
// Create an InterpretedAuditdRecord that transforms an AuditdRecord into a human-readable format

// TODO: create an interpreted AuditdRecord that takes enrichment and replaces the raw fields with the enrichment?
//
// Or maybe we should have a RawAuditd record

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditdRecord {
    pub record_type: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,

    /// Record identifier
    pub id: u64,

    pub fields: HashMap<String, FieldValue>,

    pub enrichment: HashMap<String, FieldValue>,
}

#[derive(Debug)]
struct InnerHeader {
    record_type: String,
    audit_msg: InnerAuditMsg,
}

#[derive(Debug)]
struct InnerAuditMsg {
    timestamp: u64,
    uid: u64,
}

#[derive(Debug)]
struct InnerBody {
    fields: HashMap<String, FieldValue>,
    enrichment: HashMap<String, FieldValue>,
}

// TODO: add an array variant for things like `grantors=pam_unix,pam_permit,pam_time`
// TODO: add a null variant for things like `hostname=?`
// TODO: add hexadecimal variant? That hexadecimal should be decoded or leaved as-is? Maybe
// we could interpret it in the interpret mode..?
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum FieldValue {
    Integer(u64),
    String(String),
    Map(HashMap<String, FieldValue>),
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

// TODO: return a Header Struct instead of a tuple
fn parse_header(input: &str) -> IResult<&str, InnerHeader> {
    (parse_record_type, parse_audit_msg)
        .map(|(record_type, audit_msg)| InnerHeader {
            record_type,
            audit_msg,
        })
        .parse(input)
}

fn parse_key(input: &str) -> IResult<&str, String> {
    take_until1("=").map(ToString::to_string).parse(input)
}

/// Parses a string value, which can be surrounded by single or double quotes.
fn parse_string_value(input: &str) -> IResult<&str, &str> {
    alt((
        delimited(tag("\""), take_until1("\""), tag("\"")),
        delimited(tag("'"), take_until1("'"), tag("'")),
    ))
    .parse(input)
}

/// Parses a map value, which is a string that contains a list of key-value pairs.
/// For example, it can be found in the `msg` field of auditd records, surrounded by single quotes:
///
/// `msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="jorge" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'`
fn parse_map_value(input: &str) -> IResult<&str, HashMap<String, FieldValue>> {
    parse_string_value
        .and_then(parse_key_value_list)
        .parse(input)
}

fn parse_unquoted_value(input: &str) -> IResult<&str, FieldValue> {
    // If the value is not surrounded by quotes, take all the characters until a space or the enrichment separator is found.
    // For example, in the `op` field of auditd records: `op=PAM:accounting`, the value should be a string, but
    // it is not surrounded by quotes.
    take_while1(|c: char| !c.is_space() && c != ENRICHMENT_SEPARATOR)
        .and_then(alt((
            all_consuming(parse_u64).map(FieldValue::Integer),
            // TODO: add a parse_hexadecimal parser?
            // TODO: add a parse_null parser? to parse things like `hostname=?`
            // Treat the unquoted value as an string if the previous parsers did not succeed
            // and return the input to this `alt` as-is
            consume_all.map(|s| FieldValue::String(s.to_string())),
        )))
        .parse(input)
}

/// Parses the value part of a field, the right side of the `key=value` pair.
fn parse_value(input: &str) -> IResult<&str, FieldValue> {
    alt((
        parse_map_value.map(FieldValue::Map),
        parse_string_value.map(|s| FieldValue::String(s.to_string())),
        parse_unquoted_value,
    ))
    .parse(input)
}

/// Parses a key-value pair
fn parse_key_value(input: &str) -> IResult<&str, (String, FieldValue)> {
    separated_pair(parse_key, tag("="), parse_value).parse(input)
}

/// Parses a list of key-value pairs, separated by spaces
fn parse_key_value_list(input: &str) -> IResult<&str, HashMap<String, FieldValue>> {
    separated_list1(space1, parse_key_value)
        .map(HashMap::from_iter)
        .parse(input)
}

fn parse_body(input: &str) -> IResult<&str, InnerBody> {
    // TODO: enrichment should be optional
    separated_pair(
        parse_key_value_list,
        char(ENRICHMENT_SEPARATOR),
        parse_key_value_list,
    )
    .map(|(fields, enrichment)| InnerBody { fields, enrichment })
    .parse(input)
}

fn parse_record(input: &str) -> IResult<&str, AuditdRecord> {
    // TODO: create a test that adds trailing data to the record, so all_consuming fails
    all_consuming(
        (parse_header, parse_body).map(|(header, body)| AuditdRecord {
            record_type: header.record_type,
            timestamp: header.audit_msg.timestamp,
            id: header.audit_msg.uid,
            fields: body.fields,
            // TODO: we should lowercase the enrichment keys?, so they match the ones in the body
            // Where should we modify it? Inside `parse_body` or here?
            // I think it is better here so `parse_body` just returns it raw..
            enrichment: body.enrichment,
        }),
    )
    .parse(input)
}

impl<'a> FromStr for AuditdRecord {
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_record(input)
            .finish()
            .map(|(_, record)| record)
            .map_err(|err| anyhow::anyhow!(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: create unit tests for each of the parsers.

    // TODO: add a test where one of the fields starts by a number but ends with chars, for example `pid=123abc`,
    // so we can test that the `parse_unquoted_value` parser does not parse partially as an integer

    // TODO: snapshot testing with rstest cases, read cases from a file or
    // have it hardcoded in this file?
    // Those should be integration tests
    #[test]
    fn parse() {
        let line = "type=USER_ACCT msg=audit(1725039526.208:52): pid=580903 uid=1000 auid=1000 ses=2 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct=\"jorge\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/1 res=success'\u{1d}UID=\"jorge\" AUID=\"jorge\"";
        dbg!(line.parse::<AuditdRecord>());
    }
}
