use key::parse_key;
use nom::branch::alt;
use nom::character::complete::char;
use nom::character::complete::space0;
use nom::character::complete::space1;
use nom::combinator::all_consuming;
use nom::multi::separated_list1;
use nom::sequence::{preceded, separated_pair};
use nom::{IResult, Parser};
use std::collections::BTreeMap;
use value::parse_value;

mod key;
mod value;

pub const ENRICHMENT_SEPARATOR: char = '\x1d';

#[derive(Debug, PartialEq, Eq)]
pub struct InnerBody {
    pub fields: BTreeMap<String, String>,
    pub enrichment: Option<BTreeMap<String, String>>,
}

/// Parses a key-value pair
fn parse_key_value(input: &str) -> IResult<&str, (String, String)> {
    separated_pair(parse_key, char('='), parse_value).parse(input)
}

/// Parses a list of key-value pairs, separated by spaces
pub fn parse_key_value_list(input: &str) -> IResult<&str, BTreeMap<String, String>> {
    preceded(space0, separated_list1(space1, parse_key_value))
        .map(BTreeMap::from_iter)
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

fn parse_not_enriched_body(input: &str) -> IResult<&str, InnerBody> {
    parse_key_value_list
        .map(|fields| InnerBody {
            fields,
            enrichment: None,
        })
        .parse(input)
}

pub fn parse_body(input: &str) -> IResult<&str, InnerBody> {
    all_consuming(alt((parse_enriched_body, parse_not_enriched_body))).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::regular("key=value", ("key", "value"))]
    fn test_parse_key_value(#[case] input: &str, #[case] expected: (&str, &str)) {
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
    #[case::single("key1=value1", BTreeMap::from([("key1".into(), "value1".into())]))]
    #[case::multiple("key1=value1 key2=value2 key3=value3",
        BTreeMap::from([("key1".into(), "value1".into()),
            ("key2".into(), "value2".into()),("key3".into(), "value3".into())])
    )]
    #[case::preceding_space(" key1=value1",
        BTreeMap::from([("key1".into(), "value1".into())])
    )]
    #[case::multiple_preceding_space("  key1=value1",
        BTreeMap::from([("key1".into(), "value1".into())])
    )]
    #[case::multiple_space_separator("key1=value1   key2=value2   key3=value3",
        BTreeMap::from([("key1".into(), "value1".into()),
            ("key2".into(), "value2".into()),("key3".into(), "value3".into())])
    )]
    fn test_parse_key_value_list(#[case] input: &str, #[case] expected: BTreeMap<String, String>) {
        let (remaining, result) = parse_key_value_list(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::missing_key("=value1 key2=value2")]
    #[case::missing_value("key1= key2=value2")]
    #[case::missing_key_and_value("=")]
    #[case::missing_equal("foo")]
    #[case::empty("")]
    #[case::space(" ")]
    fn test_parse_key_value_list_fails(#[case] input: &str) {
        assert!(parse_key_value_list(input).is_err());
    }

    #[rstest]
    #[case::regular(&format!("key1=value1 key2=value2{ENRICHMENT_SEPARATOR}enriched_key=enriched_value"),
        InnerBody{
            fields: BTreeMap::from([("key1".into(), "value1".into()), ("key2".into(), "value2".into())]),
            enrichment: Some(BTreeMap::from([("enriched_key".into(), "enriched_value".into())]))
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
    #[case::invalid_key_value("foo")]
    #[case::empty("")]
    fn test_parse_enriched_body_fails(#[case] input: &str) {
        assert!(parse_body(input).is_err());
    }

    #[rstest]
    #[case::regular("key1=value1 key2=value2",
        InnerBody{
            fields: BTreeMap::from([("key1".into(), "value1".into()), ("key2".into(), "value2".into())]),
            enrichment: None
        }
    )]
    fn test_parse_unenriched_body(#[case] input: &str, #[case] expected: InnerBody) {
        let (remaining, result) = parse_body(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::invalid_key_value("foo")]
    #[case::empty("")]
    fn test_parse_unenriched_body_fails(#[case] input: &str) {
        assert!(parse_body(input).is_err());
    }

    #[rstest]
    #[case::enriched(&format!("key1=value1 key2=value2{ENRICHMENT_SEPARATOR}enriched_key=enriched_value"),
        InnerBody{
            fields: BTreeMap::from([("key1".into(), "value1".into()), ("key2".into(), "value2".into())]),
            enrichment: Some(BTreeMap::from([("enriched_key".into(), "enriched_value".into())]))
        }
    )]
    #[case::not_enriched("key1=value1 key2=value2",
        InnerBody{
            fields: BTreeMap::from([("key1".into(), "value1".into()), ("key2".into(), "value2".into())]),
            enrichment: None
        }
    )]
    fn test_parse_body(#[case] input: &str, #[case] expected: InnerBody) {
        let (remaining, result) = parse_body(input).unwrap();
        assert!(remaining.is_empty());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::trailing_data("key1=value1 key2=value2 foo")]
    #[case::invalid_key_value("foo")]
    #[case::empty("")]
    fn test_parse_body_fails(#[case] input: &str) {
        assert!(dbg!(parse_body(input)).is_err());
    }

    #[test]
    fn test_parse_body_all_consuming_fails() {
        let line = format!(
            "key=value{ENRICHMENT_SEPARATOR}enriched_key=enriched_value{ENRICHMENT_SEPARATOR}"
        );

        assert!(dbg!(parse_body(&line)).is_err());
    }
}
