use static_assertions::const_assert;

// Capabilities are extracted from https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h
// We should mantain these in sync with the kernel version.
pub const CAPABILITIES: [&str; 41] = [
    // TODO: lowercase or should we output `CAP_CHOWN` as they are named in the kernel?
    "chown",
    "dac_override",
    "dac_read_search",
    "fowner",
    "fsetid",
    "kill",
    "setgid",
    "setuid",
    "setpcap",
    "linux_immutable",
    "net_bind_service",
    "net_broadcast",
    "net_admin",
    "net_raw",
    "ipc_lock",
    "ipc_owner",
    "sys_module",
    "sys_rawio",
    "sys_chroot",
    "sys_ptrace",
    "sys_pacct",
    "sys_admin",
    "sys_boot",
    "sys_nice",
    "sys_resource",
    "sys_time",
    "sys_tty_config",
    "mknod",
    "lease",
    "audit_write",
    "audit_control",
    "setfcap",
    "mac_override",
    "mac_admin",
    "syslog",
    "wake_alarm",
    "block_suspend",
    "audit_read",
    "perfmon",
    "bpf",
    "checkpoint_restore",
];

pub fn resolve_capability_bitmap(cap_bitmap: u64) -> Vec<String> {
    // Note that the size of capabilities bitmap (and therefore, the number
    // of capabilities) should be at most 64.
    const_assert!(CAPABILITIES.len() <= 64);

    CAPABILITIES
        .iter()
        .enumerate()
        .filter_map(|(i, cap_name)| {
            if (cap_bitmap >> i) & 1 == 1 {
                Some(cap_name)
            } else {
                None
            }
        })
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest(
        input,
        expected,
        case(0b0, vec![]),
        case(0b1, vec!["chown"]),
        case(0b10, vec!["dac_override"]),
        case(0b11, vec!["chown", "dac_override"]),
        case(0b100, vec!["dac_read_search"]),
        case(0b1010_1010, vec!["dac_override","fowner","kill","setuid"]),
        case(0b1_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111, CAPABILITIES.to_vec()),
        case(u64::MAX, CAPABILITIES.to_vec())
    )]
    fn test_resolve_capability_bitmap(input: u64, expected: Vec<&str>) {
        let result = resolve_capability_bitmap(input);
        assert_eq!(result, expected);
    }
}
