use nom::{IResult, Parser, bytes::complete::take_until1};

pub fn parse_key(input: &str) -> IResult<&str, String> {
    take_until1("=").map(ToString::to_string).parse(input)
}
