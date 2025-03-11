use nom::{IResult, Parser, bytes::complete::take_until1};

/// Parses a key from a key-value pair which is separated by an equal sign.
pub fn parse_key(input: &str) -> IResult<&str, String> {
    take_until1("=").map(ToString::to_string).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::regular("key=", "key")]
    #[case::with_space("key =", "key ")]
    #[case::numeric("123=", "123")]
    #[case::quoted("\"key\"=", "\"key\"")]
    #[case::quoted_with_space("\"key with space\"=", "\"key with space\"")]
    fn test_parse_key(#[case] input: &str, #[case] expected: &str) {
        let (remaining, result) = parse_key(input).unwrap();
        assert_eq!(remaining, "=");
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::without_key("=")]
    #[case::without_separator("key")]
    #[case::empty_input("")]
    fn test_parse_key_fails(#[case] input: &str) {
        assert!(parse_key(input).is_err());
    }
}
