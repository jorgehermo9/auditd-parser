use crate::FieldValue;
use key::parse_key;
use nom::branch::alt;
use nom::character::complete::char;
use nom::combinator::all_consuming;
use nom::multi::separated_list1;
use nom::sequence::separated_pair;
use nom::{IResult, Parser};
use std::collections::HashMap;
use value::parse_value;

mod key;
mod value;

const ENRICHMENT_SEPARATOR: char = '\x1d';

#[derive(Debug, PartialEq, Eq)]
pub struct InnerBody {
    pub fields: HashMap<String, FieldValue>,
    pub enrichment: Option<HashMap<String, FieldValue>>,
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

fn parse_enriched_body(input: &str) -> IResult<&str, InnerBody> {
    separated_pair(
        parse_key_value_list,
        char(ENRICHMENT_SEPARATOR),
        parse_key_value_list,
    )
    .map(|(fields, enrichment)| InnerBody {
        fields,
        enrichment: Some(enrichment),
    })
    .parse(input)
}

pub fn parse_unenriched_body(input: &str) -> IResult<&str, InnerBody> {
    parse_key_value_list
        .map(|fields| InnerBody {
            fields,
            enrichment: None,
        })
        .parse(input)
}

pub fn parse_body(input: &str) -> IResult<&str, InnerBody> {
    all_consuming(alt((parse_enriched_body, parse_unenriched_body))).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::regular("key=value", ("key", "value".into()))]
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
        assert!(parse_key_value_list(input).is_err());
    }

    #[rstest]
    #[case::regular(&format!("key1=value1 key2=value2{ENRICHMENT_SEPARATOR}enriched_key=enriched_value"),
        InnerBody{
            fields: HashMap::from([("key1".into(), "value1".into()), ("key2".into(), "value2".into())]),
            enrichment: Some(HashMap::from([("enriched_key".into(), "enriched_value".into())]))
        }
    )]
    fn test_parse_enriched_body(#[case] input: &str, #[case] expected: InnerBody) {
        let (remaining, result) = parse_body(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::empty_enrichment(&format!("key1=value1 key2=value2{ENRICHMENT_SEPARATOR}"))]
    #[case::empty_fields(&format!("{ENRICHMENT_SEPARATOR}enriched_key=enriched_value"))]
    #[case::empty_enrichment_and_fields(&format!("{ENRICHMENT_SEPARATOR}"))]
    #[case::empty_input("")]
    fn test_parse_enriched_body_fails(#[case] input: &str) {
        dbg!(parse_body(input));
        assert!(parse_body(input).is_err());
    }

    // TODO: add tests for unenriched body & body
}
