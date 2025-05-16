use std::fmt::{self, Display, Formatter};

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
