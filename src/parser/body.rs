use crate::FieldValue;
use crate::utils::burp;
use nom::AsChar;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until1, take_while1};
use nom::character::complete::{char, space1, u64 as parse_u64};
use nom::combinator::all_consuming;
use nom::multi::separated_list1;
use nom::sequence::{delimited, separated_pair};
use nom::{IResult, Parser};
use std::collections::HashMap;

const ENRICHMENT_SEPARATOR: char = '\x1d';

#[derive(Debug)]
pub struct InnerBody {
    pub fields: HashMap<String, FieldValue>,
    pub enrichment: HashMap<String, FieldValue>,
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

fn parse_quoted_value(input: &str) -> IResult<&str, FieldValue> {
    parse_string_value
        .and_then(alt((
            // Parses a map value, which is a string that contains a list of key-value pairs.
            // For example, it can be found in the `msg` field of auditd records, surrounded by single quotes:
            // `msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="jorge" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'`
            parse_key_value_fields.map(FieldValue::Map),
            // Treat the quoted value as an string if the previous parsers did not succeed
            // and return the input to this `alt` as-is
            burp.map(|s| FieldValue::String(s.to_string())),
        )))
        .parse(input)
}

fn parse_primitive_value(input: &str) -> IResult<&str, FieldValue> {
    // TODO: add `null` variant
    // TODO: add hexadecimal variant? Or maybe we should interpret it in a different step?
    // based in field name
    all_consuming(alt((parse_u64.map(FieldValue::Integer),))).parse(input)
}

fn parse_unquoted_value(input: &str) -> IResult<&str, FieldValue> {
    // If the value is not surrounded by quotes, take all the characters until a space or the enrichment separator is found.
    // For example, in the `op` field of auditd records: `op=PAM:accounting`, the value should be a string, but
    // it is not surrounded by quotes.
    take_while1(|c: char| !c.is_space() && c != ENRICHMENT_SEPARATOR)
        .and_then(alt((
            parse_primitive_value,
            // TODO: add a parse_hexadecimal parser?
            // TODO: add a parse_null parser? to parse things like `hostname=?`
            // Treat the unquoted value as an string if the previous parsers did not succeed
            // and return the input to this `alt` as-is
            burp.map(|s| FieldValue::String(s.to_string())),
        )))
        .parse(input)
}

/// Parses the value part of a field, the right side of the `key=value` pair.
fn parse_value(input: &str) -> IResult<&str, FieldValue> {
    alt((parse_quoted_value, parse_unquoted_value)).parse(input)
}

/// Parses a key-value pair
fn parse_key_value(input: &str) -> IResult<&str, (String, FieldValue)> {
    separated_pair(parse_key, tag("="), parse_value).parse(input)
}

/// Parses a list of key-value pairs, separated by spaces
fn parse_key_value_fields(input: &str) -> IResult<&str, HashMap<String, FieldValue>> {
    separated_list1(space1, parse_key_value)
        .map(HashMap::from_iter)
        .parse(input)
}

pub fn parse_body(input: &str) -> IResult<&str, InnerBody> {
    // TODO: enrichment should be optional
    // maybe we should have something like
    // alt(parse_key_value_list, separated_pair(...))
    // we may have to move the `all_consuming` of the `parse_record` to this function
    separated_pair(
        parse_key_value_fields,
        char(ENRICHMENT_SEPARATOR),
        parse_key_value_fields,
    )
    .map(|(fields, enrichment)| InnerBody { fields, enrichment })
    .parse(input)
}
