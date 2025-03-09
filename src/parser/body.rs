use crate::FieldValue;
use key::parse_key;
use nom::bytes::complete::tag;
use nom::character::complete::{char, space1};
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
    separated_pair(parse_key, tag("="), parse_value).parse(input)
}

/// Parses a list of key-value pairs, separated by spaces
fn parse_key_value_list(input: &str) -> IResult<&str, HashMap<String, FieldValue>> {
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
        parse_key_value_list,
        char(ENRICHMENT_SEPARATOR),
        parse_key_value_list,
    )
    .map(|(fields, enrichment)| InnerBody { fields, enrichment })
    .parse(input)
}
