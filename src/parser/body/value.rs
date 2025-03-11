use crate::FieldValue;
use crate::utils::burp;
use nom::AsChar;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until1, take_while, take_while1};
use nom::character::complete::{char, u64 as parse_u64};
use nom::combinator::all_consuming;
use nom::sequence::delimited;
use nom::{IResult, Parser};

use super::{ENRICHMENT_SEPARATOR, parse_key_value_list};

// TODO: reorder these functions so we go from high-level to low-level

/// Parses a string value, which can be surrounded by single or double quotes.
fn parse_string_value(input: &str) -> IResult<&str, &str> {
    const DOUBLE_QUOTE: char = '"';
    const SINGLE_QUOTE: char = '\'';

    // TODO: handle scaped double quote inside double quoted string with `escaped` parser
    // TODO: handle scaped single quote inside single quoted string with `escaped` parser
    alt((
        delimited(
            char(DOUBLE_QUOTE),
            take_while(|c| c != DOUBLE_QUOTE),
            char(DOUBLE_QUOTE),
        ),
        delimited(
            char(SINGLE_QUOTE),
            take_while(|c| c != SINGLE_QUOTE),
            char(SINGLE_QUOTE),
        ),
    ))
    .parse(input)
}

fn parse_quoted_value(input: &str) -> IResult<&str, FieldValue> {
    parse_string_value
        .and_then(alt((
            // Parses a map value, which is a string that contains a list of key-value pairs.
            // For example, it can be found in the `msg` field of auditd records, surrounded by single quotes:
            // `msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct="jorge" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success'`
            parse_key_value_list.map(FieldValue::Map),
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
pub fn parse_value(input: &str) -> IResult<&str, FieldValue> {
    alt((parse_quoted_value, parse_unquoted_value)).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    #[rstest]
    #[case::double_quoted("\"foo\"", "foo")]
    #[case::single_quoted("'foo'", "foo")]
    #[case::double_quoted_with_space("\"foo bar\"", "foo bar")]
    #[case::single_quoted_with_space("'foo bar'", "foo bar")]
    #[case::double_quoted_with_single_quote_inside("\"foo'bar\"", "foo'bar")]
    #[case::single_quoted_with_double_quote_inside("'foo\"bar'", "foo\"bar")]
    #[case::double_quoted_empty_string("\"\"", "")]
    #[case::single_quoted_empty_string("''", "")]
    fn test_parse_string_value(#[case] input: &str, #[case] expected: &str) {
        let (remaining, result) = parse_string_value(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::unquoted("foo")]
    #[case::unquoted_with_space("foo bar")]
    #[case::mixed_quotes("\"foo'")]
    #[case::double_quoted_not_terminated("\"foo")]
    #[case::single_quoted_not_terminated("'foo")]
    #[case::double_quoted_not_preceded("foo\"")]
    #[case::single_quoted_not_preceded("foo'")]
    #[case::empty_input("")]
    fn test_parse_string_value_fails(#[case] input: &str) {
        assert!(parse_string_value(input).is_err());
    }

    // FIXME: this tests should not fail. We should treat escaped quotes properly
    #[rstest]
    #[case::escaped_double_quote(r#""foo\"bar""#, r#"foo"bar"#)]
    #[case::escaped_single_quote(r#"'foo\'bar'"#, r#"foo'bar"#)]
    fn fixme_parse_string_value(#[case] input: &str, #[case] expected: &str) {
        let (_, result) = parse_string_value(input).unwrap();
        assert_ne!(result, expected);
    }
}
