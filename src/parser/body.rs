use crate::FieldValue;
use key::parse_key;
use nom::character::complete::char;
use nom::multi::separated_list1;
use nom::sequence::separated_pair;
use nom::{IResult, Parser};
use std::collections::HashMap;
use value::parse_value;

mod key;
mod value;

const ENRICHMENT_SEPARATOR: char = '\x1d';

#[derive(Debug)]
pub struct InnerBody {
    pub fields: HashMap<String, FieldValue>,
    pub enrichment: HashMap<String, FieldValue>,
}

/// Parses a key-value pair
fn parse_key_value(input: &str) -> IResult<&str, (String, FieldValue)> {
    separated_pair(parse_key, char('='), parse_value).parse(input)
}

/// Parses a list of key-value pairs, separated by spaces
fn parse_key_value_list(input: &str) -> IResult<&str, HashMap<String, FieldValue>> {
    separated_list1(char(' '), parse_key_value)
        .map(HashMap::from_iter)
        .parse(input)
}

pub fn parse_body(input: &str) -> IResult<&str, InnerBody> {
    // TODO: enrichment should be optional
    // maybe we should have something like
    // alt(parse_key_value_list, separated_pair(...))
    // we may have to move the `all_consuming` of the `parse_record` to this function
    separated_pair(
        parse_key_value_list,
        char(ENRICHMENT_SEPARATOR),
        parse_key_value_list,
    )
    .map(|(fields, enrichment)| InnerBody { fields, enrichment })
    .parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("key=value", ("key", "value".into()))]
    fn test_parse_key_value(#[case] input: &str, #[case] expected: (&str, FieldValue)) {
        let (expected_key, expected_value) = expected;
        let (remaining, (key, value)) = parse_key_value(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(key, expected_key);
        assert_eq!(value, expected_value);
    }

    #[rstest]
    #[case::missing_separator("keyvalue")]
    #[case::missing_key("=value")]
    #[case::missing_value("key=")]
    #[case::missing_key_and_value("=")]
    #[case::empty("")]
    fn test_parse_key_value_fails(#[case] input: &str) {
        assert!(parse_key_value(input).is_err());
    }

    #[rstest]
    #[case::single("key1=value1", HashMap::from([("key1".into(), "value1".into())]))]
    #[case::multiple("key1=value1 key2=value2 key3=value3",
        HashMap::from([("key1".into(), "value1".into()),
        ("key2".into(), "value2".into()),("key3".into(), "value3".into())]))]
    fn test_parse_key_value_list(
        #[case] input: &str,
        #[case] expected: HashMap<String, FieldValue>,
    ) {
        let (remaining, result) = parse_key_value_list(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::missing_key("=value1 key2=value2")]
    #[case::missing_value("key1= key2=value2")]
    #[case::missing_key_and_value("=")]
    #[case::empty("")]
    fn test_parse_key_value_list_fails(#[case] input: &str) {
        dbg!(parse_key_value_list(input));
        assert!(parse_key_value_list(input).is_err());
    }
}
