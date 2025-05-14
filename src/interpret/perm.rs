const AUDIT_PERM_EXEC: u32 = 0b0001;
const AUDIT_PERM_WRITE: u32 = 0b0010;
const AUDIT_PERM_READ: u32 = 0b0100;
const AUDIT_PERM_ATTR: u32 = 0b1000;

pub fn resolve_perm_mask(perm_mask: u32) -> Vec<String> {
    // Kernel uses `0x00` value as all permissiones enabled`0x0F`
    // Ref: https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L1034
    let perm_mask = if perm_mask == 0 { 0b1111 } else { perm_mask };

    let mut perms = vec![];

    if (perm_mask & AUDIT_PERM_EXEC) == AUDIT_PERM_EXEC {
        perms.push("exec".into());
    }
    if (perm_mask & AUDIT_PERM_WRITE) == AUDIT_PERM_WRITE {
        perms.push("write".into());
    }

    if (perm_mask & AUDIT_PERM_READ) == AUDIT_PERM_READ {
        perms.push("read".into());
    }

    if (perm_mask & AUDIT_PERM_ATTR) == AUDIT_PERM_ATTR {
        perms.push("attr".into());
    }

    perms
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::all_zero(0, vec!["exec", "write", "read", "attr"])]
    #[case::all_perms_set(0b1111, vec!["exec", "write", "read", "attr"])]
    #[case::all_bits_set(u32::MAX, vec!["exec", "write", "read", "attr"])]
    #[case::none_perms(0b10000, vec![])]
    #[case::exec(0b0001, vec!["exec"])]
    #[case::write(0b0010, vec!["write"])]
    #[case::read(0b0100, vec!["read"])]
    #[case::attr(0b1000, vec!["attr"])]
    #[case::exec_write(0b0011, vec!["exec", "write"])]
    #[case::read_attr(0b1100, vec!["read", "attr"])]
    #[case::exec_attr(0b1001, vec!["exec", "attr"])]
    #[case::write_read(0b0110, vec!["write", "read"])]
    fn test_resolve_perm_mask(#[case] input: u32, #[case] expected: Vec<&str>) {
        let result = resolve_perm_mask(input);
        assert_eq!(result, expected);
    }
}
