pub fn parse_proctitle(bytes: &[u8]) -> String {
    // Proctitle arguments are null-byte separated
    // Ref: https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L1000
    bytes
        .split(|&b| b == 0)
        .map(|arg| String::from_utf8_lossy(arg).to_string())
        .collect::<Vec<String>>()
        // TODO: join or not?
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::no_args("foo", "foo")]
    #[case::single_arg("foo\0bar", "foo bar")]
    #[case::multiple_args("foo\0bar\0baz", "foo bar baz")]
    #[case::only_args("\0foo\0bar\0baz", " foo bar baz")]
    #[case::empty("", "")]
    fn test_parse_proctitle(#[case] input: &str, #[case] expected: &str) {
        let result = parse_proctitle(input.as_bytes());
        assert_eq!(result, expected);
    }

    #[test]
    fn test_parse_proctitle_non_utf8() {
        let result = parse_proctitle(b"foo\0b\xffar");
        assert_eq!(result, "foo b�ar");
    }
}
