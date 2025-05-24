use std::fmt::{self, Display, Formatter};

// Constants extracted from https://github.com/torvalds/linux/blob/4856ebd997159f198e3177e515bda01143727463/include/uapi/linux/audit.h#L171
#[derive(Debug, PartialEq)]
pub enum AuditFlag {
    User,
    Task,
    Entry,
    Watch,
    Exit,
    Exclude,
    Filesystem,
    IoUringExit,
}

impl Display for AuditFlag {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // Display inspired by https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/lib/flagtab.h#L25C4-L25C21
        match self {
            AuditFlag::User => write!(f, "user"),
            AuditFlag::Task => write!(f, "task"),
            AuditFlag::Entry => write!(f, "entry"),
            AuditFlag::Watch => write!(f, "watch"),
            AuditFlag::Exit => write!(f, "exit"),
            AuditFlag::Exclude => write!(f, "exclude"),
            AuditFlag::Filesystem => write!(f, "filesystem"),
            AuditFlag::IoUringExit => write!(f, "io-uring-exit"),
        }
    }
}

pub fn resolve_audit_flag(audit_flag: u64) -> Option<AuditFlag> {
    let audit_flag = match audit_flag {
        0 => AuditFlag::User,
        1 => AuditFlag::Task,
        2 => AuditFlag::Entry,
        3 => AuditFlag::Watch,
        4 => AuditFlag::Exit,
        5 => AuditFlag::Exclude,
        6 => AuditFlag::Filesystem,
        7 => AuditFlag::IoUringExit,
        _ => return None,
    };
    Some(audit_flag)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::user(0, Some(AuditFlag::User))]
    #[case::task(1, Some(AuditFlag::Task))]
    #[case::entry(2, Some(AuditFlag::Entry))]
    #[case::watch(3, Some(AuditFlag::Watch))]
    #[case::exit(4, Some(AuditFlag::Exit))]
    #[case::exclude(5, Some(AuditFlag::Exclude))]
    #[case::filesystem(6, Some(AuditFlag::Filesystem))]
    #[case::io_uring(7, Some(AuditFlag::IoUringExit))]
    #[case::invalid(8, None)]
    #[case::max_u64(u64::MAX, None)]
    fn test_resolve_audit_flag(#[case] input: u64, #[case] expected: Option<AuditFlag>) {
        let result = resolve_audit_flag(input);
        assert_eq!(result, expected);
    }
}
