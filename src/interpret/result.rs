use std::fmt::{self, Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum Result {
    Failed,
    Success,
    Unset,
}

pub fn resolve_result(result: &str) -> Result {
    // First, try to parse it as a 32-bit unsigned integer
    // Ref: https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L1459
    if let Ok(result) = result.parse::<u32>() {
        // Ref: https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L540
        return match result {
            0 => Result::Failed,
            1 => Result::Success,
            _ => Result::Unset,
        };
    }

    // If it's not a number, try to parse it as a string
    // Ref: https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L1469
    // Auparse does not validate the string, but we will match to it in order to have it typed
    match result {
        "failed" => Result::Failed,
        "success" => Result::Success,
        _ => Result::Unset,
    }
}

impl Display for Result {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Result::Failed => write!(f, "failed"),
            Result::Success => write!(f, "success"),
            Result::Unset => write!(f, "unset"),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::failed("0", Result::Failed)]
    #[case::success("1", Result::Success)]
    #[case::unset("2", Result::Unset)]
    #[case::failed_string("failed", Result::Failed)]
    #[case::success_string("success", Result::Success)]
    #[case::foo("foo", Result::Unset)]
    fn test_resolve_result(#[case] input: &str, #[case] expected: Result) {
        let result = resolve_result(input);
        assert_eq!(result, expected);
    }
}
