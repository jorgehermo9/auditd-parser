// This represents both an uid and a gid
#[derive(Debug, PartialEq, Eq)]
pub enum Uid {
    Root,
    User(i64),
    Unset,
}

pub fn resolve_uid(uid: i64) -> Uid {
    // inspired from https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L553C33-L553C38
    // Uid and Gid are treated the same
    match uid {
        0 => Uid::Root,
        // 4294967295 is -1 `uid_t` (signed 32-bit integer) in the kernel.
        // This is used to represent unset uid/gid.
        // In the kernel, the uid -1 is sometimes printed as `%d` (and we would see -1) and sometimes as `%u` (and we would see 4294967295)
        // Ref: https://github.com/search?q=repo%3Atorvalds%2Flinux+%22uid%3D%25%22+%22audit_log%22&type=code
        4_294_967_295 | -1 => Uid::Unset,
        _ => Uid::User(uid),
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::root(0, Uid::Root)]
    #[case::unset(4_294_967_295, Uid::Unset)]
    #[case::unset_negative(-1, Uid::Unset)]
    #[case::user(1000, Uid::User(1000))]
    fn test_resolve_uid(#[case] input: i64, #[case] expected: Uid) {
        let result = resolve_uid(input);
        assert_eq!(result, expected);
    }
}
