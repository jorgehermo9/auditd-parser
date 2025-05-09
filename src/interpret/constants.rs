// The constants of this file are extracted from
// https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/typetab.h#L75

// TODO: interpret a[[:digit:]+]\[.*\]

/// Those fields corresponds to `AUPARSE_TYPE_ESCAPED` fields in auparse
pub const ESCAPED_FIELD_NAMES: [&str; 36] = [
    "path",
    "comm",
    "exe",
    "file",
    "name", // TODO: This is actually `AUPARSE_TYPE_ESCAPED_FILE`, check if its the same
    "watch",
    "cwd",
    "cmd",
    "acct",
    "dir",
    "key", // TODO: this is actually `AUPARSE_TYPE_ESCAPED_KEY`, check if its the same
    "vm",
    "old-chardev",
    "new-chardev",
    "old-disk",
    "new-disk",
    "old-fs",
    "new-fs",
    "old-net",
    "new-net",
    "device",
    "cgroup",
    "apparmor",
    "operation",
    "denied_mask",
    "info",
    "profile",
    "requested_mask",
    "old-rng",
    "new-rng",
    "ocomm",
    "grp",
    "new_group",
    "invalid_context",
    "sw",
    "root_dir",
];
