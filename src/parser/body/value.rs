use nom::AsChar;
use nom::branch::alt;
use nom::bytes::complete::{take_while, take_while1};
use nom::character::complete::char;
use nom::sequence::delimited;
use nom::{IResult, Parser};

use super::ENRICHMENT_SEPARATOR;

// TODO: reorder these functions so we go from high-level to low-level

/// Parses a string value, which can be surrounded by single or double quotes.
// TODO: create a parse_string method and use it also in the key parser?
fn parse_quoted_value(input: &str) -> IResult<&str, &str> {
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

// TODO: the maybe we have to make a parser out of the `take_while1(..)` as it is repeated
// in parse_key.
fn parse_unquoted_value(input: &str) -> IResult<&str, &str> {
    // If the value is not surrounded by quotes, take all the characters until a space or the enrichment separator is found.
    // For example, in the `op` field of auditd records: `op=PAM:accounting`, the value should be a string, but
    // it is not surrounded by quotes.
    // TODO: use take_while0?
    take_while1(|c: char| !c.is_space() && c != ENRICHMENT_SEPARATOR).parse(input)
}

/// Parses the value part of a field, the right side of the `key=value` pair.
pub fn parse_value(input: &str) -> IResult<&str, String> {
    alt((parse_quoted_value, parse_unquoted_value))
        .map(ToString::to_string)
        .parse(input)
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
    #[case::map_single_entry("'key=value'", "key=value")]
    #[case::map_multiple_entries(
        "'key1=value1 key2=value2 key3=value3'",
        "key1=value1 key2=value2 key3=value3"
    )]
    #[case::double_quoted_map("\"key1=value1 key2=value2\"", "key1=value1 key2=value2")]
    // FIXME: this tests should not fail. We should treat escaped quotes properly
    // #[case::escaped_double_quote(r#""foo\"bar""#, r#"foo"bar"#)]
    // #[case::escaped_single_quote("'foo\'bar'", "foo'bar")]
    fn test_parse_quoted_value(#[case] input: &str, #[case] expected: &str) {
        let (remaining, result) = parse_quoted_value(input).unwrap();
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
    #[case::empty("")]
    fn test_parse_quoted_value_fails(#[case] input: &str) {
        assert!(parse_quoted_value(input).is_err());
    }

    #[rstest]
    #[case::unquoted_string("foo", "foo")]
    #[case::number("123", "123")]
    fn test_parse_unquoted_value(#[case] input: &str, #[case] expected: &str) {
        let (remaining, result) = parse_unquoted_value(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::space("foo bar", "foo", ' ', " bar")]
    #[case::enrichment_separator(&format!("foo{ENRICHMENT_SEPARATOR}bar"), "foo",
        ENRICHMENT_SEPARATOR, &format!("{ENRICHMENT_SEPARATOR}bar"))]
    fn test_parse_unquoted_value_stops_at_delimiter(
        #[case] input: &str,
        #[case] expected: &str,
        #[case] delimiter: char,
        #[case] expected_remaining: &str,
    ) {
        let (remaining, result) = parse_unquoted_value(input).unwrap();
        let first_remaining_char = remaining.chars().next().expect("remaining is empty");
        assert_eq!(first_remaining_char, delimiter);
        assert_eq!(remaining, expected_remaining);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::empty("")]
    #[case::only_space(" ")]
    #[case::only_enrichment_separator(&ENRICHMENT_SEPARATOR.to_string())]
    fn test_parse_unquoted_value_fails(#[case] input: &str) {
        assert!(parse_unquoted_value(input).is_err());
    }

    #[rstest]
    #[case::double_quoted_string("\"foo\"", "foo")]
    #[case::single_quoted_string("'foo'", "foo")]
    #[case::unquoted_string("foo", "foo")]
    #[case::map("'key=value'", "key=value")]
    #[case::number("123", "123")]
    fn test_parse_value(#[case] input: &str, #[case] expected: &str) {
        let (remaining, result) = parse_value(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::empty("")]
    #[case::only_space(" ")]
    #[case::only_enrichment_separator(&ENRICHMENT_SEPARATOR.to_string())]
    fn test_parse_value_fails(#[case] input: &str) {
        assert!(parse_value(input).is_err());
    }
}
