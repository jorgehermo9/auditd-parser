pub fn resolve_success(success: &str) -> Option<bool> {
    // Extracted from:
    // https://github.com/torvalds/linux/blob/4856ebd997159f198e3177e515bda01143727463/kernel/auditsc.c#L1651
    // and
    // https://github.com/torvalds/linux/blob/master/include/linux/string_choices.h#L68
    match success {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::yes("yes", Some(true))]
    #[case::no("no", Some(false))]
    #[case::unknown("foo", None)]
    fn test_resolve_success(#[case] input: &str, #[case] expected: Option<bool>) {
        let result = resolve_success(input);
        assert_eq!(result, expected);
    }
}
