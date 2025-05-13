// Capabilities are extracted from https://github.com/torvalds/linux/blob/master/include/uapi/linux/capability.h
// We should mantain these in sync with the kernel version.
// Right now, capability format is the same as in kubernetes (CAP_XX in kernel-> XX in this parser)
// Ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container
pub const CAPABILITIES: [&str; 41] = [
    // TODO: uppercase, lowercase (without CAP_) or should we output `CAP_CHOWN` as they are named in the kernel?
    // or as they are output in `capsh --decode=0000001fffffffff``? (e.g. `cap_chown`)
    // For example, in the socket family, we output `AF_INET` instead of `INET`
    "CHOWN",
    "DAC_OVERRIDE",
    "DAC_READ_SEARCH",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "LINUX_IMMUTABLE",
    "NET_BIND_SERVICE",
    "NET_BROADCAST",
    "NET_ADMIN",
    "NET_RAW",
    "IPC_LOCK",
    "IPC_OWNER",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_CHROOT",
    "SYS_PTRACE",
    "SYS_PACCT",
    "SYS_ADMIN",
    "SYS_BOOT",
    "SYS_NICE",
    "SYS_RESOURCE",
    "SYS_TIME",
    "SYS_TTY_CONFIG",
    "MKNOD",
    "LEASE",
    "AUDIT_WRITE",
    "AUDIT_CONTROL",
    "SETFCAP",
    "MAC_OVERRIDE",
    "MAC_ADMIN",
    "SYSLOG",
    "WAKE_ALARM",
    "BLOCK_SUSPEND",
    "AUDIT_READ",
    "PERFMON",
    "BPF",
    "CHECKPOINT_RESTORE",
];

const UNKNOWN_CAPABILITY: &str = "UNKNOWN";

/// Note that the size of capabilities bitmap (and therefore, the number
/// of capabilities) should be at most 64.
///
/// If a capability name is not found in the CAPABILITIES array, it will be
/// resolved as `UNKNOWN`.
pub fn resolve_capability_bitmap(cap_bitmap: u64) -> Vec<String> {
    let bits = std::mem::size_of_val(&cap_bitmap) * 8;
    (0..bits)
        .filter_map(|i| {
            if ((cap_bitmap >> i) & 1) == 1 {
                let capability = CAPABILITIES.get(i).copied().unwrap_or(UNKNOWN_CAPABILITY);
                Some(capability)
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
        case(0b1, vec!["CHOWN"]),
        case(0b10, vec!["DAC_OVERRIDE"]),
        case(0b11, vec!["CHOWN", "DAC_OVERRIDE"]),
        case(0b100, vec!["DAC_READ_SEARCH"]),
        case(0b1010_1010, vec!["DAC_OVERRIDE","FOWNER","KILL","SETUID"]),
        case(0b1_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111, CAPABILITIES.to_vec()),
    )]
    fn test_resolve_capability_bitmap(input: u64, expected: Vec<&str>) {
        let result = resolve_capability_bitmap(input);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_resolve_capability_bitmap_with_unknown_capability() {
        let result =
            resolve_capability_bitmap(0b11_1111_1111_1111_1111_1111_1111_1111_1111_1111_1111);
        let mut expected = CAPABILITIES.to_vec();
        expected.push(UNKNOWN_CAPABILITY);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_resolve_capability_bitmap_with_all_bits_set() {
        let result = resolve_capability_bitmap(u64::MAX);
        let num_capabilities = CAPABILITIES.len();
        let max_unknown_capabilities = 64 - num_capabilities;

        let mut expected = CAPABILITIES.to_vec();
        expected.append(&mut vec![UNKNOWN_CAPABILITY; max_unknown_capabilities]);

        assert_eq!(result, expected);
    }
}
