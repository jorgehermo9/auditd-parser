use nom::{
    AsChar, IResult, Parser, bytes::complete::take_while1, character::complete::char,
    combinator::peek, sequence::terminated,
};

use super::ENRICHMENT_SEPARATOR;

/// Parses a key from a key-value pair which is separated by an equal sign.
/// The key is parsed unescaped.
// TODO: parse the key scaped as we do with `parse_quoted_value`? should we do
// parsing for quoted strings propertly and use it here?
pub fn parse_key(input: &str) -> IResult<&str, String> {
    // Do not allow for invalid key characters such as spaces, enrichment separator,
    // or the equal sign which is the separator between the key and the value.
    terminated(
        // TODO: this is duplicated from the `parse_unquoted_value`. Maybe we should
        // factor that out into a common parser.
        take_while1(|c: char| c != '=' && !c.is_space() && c != ENRICHMENT_SEPARATOR),
        // Ensure that the parsed key terminates with an equal sign, but do not consume it
        peek(char('=')),
    )
    .map(ToString::to_string)
    .parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::regular("key=", "key")]
    #[case::numeric("123=", "123")]
    #[case::quoted("\"key\"=", "\"key\"")]
    fn test_parse_key(#[case] input: &str, #[case] expected: &str) {
        let (remaining, result) = parse_key(input).unwrap();
        assert_eq!(remaining, "=");
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::without_key("=")]
    #[case::without_separator("key")]
    #[case::empty_input("")]
    // We do not allow for spaces in the key. The parsing is very similar
    // to what we have in `parse_unquoted_value`
    #[case::with_space("key =")]
    #[case::quoted_with_space("\"key with space\"=")]
    fn test_parse_key_fails(#[case] input: &str) {
        assert!(parse_key(input).is_err());
    }
}
