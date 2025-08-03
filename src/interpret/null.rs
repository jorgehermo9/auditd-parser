//! This module provides a function to check if a given string is considered a "null" value.

const NULL_VALUES: [&str; 3] = ["?", "(none)", "(null)"];

pub fn is_null_value(value: &str) -> bool {
    NULL_VALUES.contains(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case("?", true)]
    #[case("(none)", true)]
    #[case("(null)", true)]
    #[case("null", false)]
    #[case("foo", false)]
    #[case(" ", false)]
    #[case("", false)]
    fn test_is_null_value(#[case] input: &str, #[case] expected: bool) {
        let result = is_null_value(input);
        assert_eq!(result, expected);
    }
}
