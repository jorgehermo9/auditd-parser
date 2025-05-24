// The constants of this file are extracted from
// https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/typetab.h#L75

const ESCAPED_FIELD_NAMES: [&str; 36] = [
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

const UID_FIELD_NAMES: [&str; 13] = [
    "auid",
    "uid",
    "euid",
    "suid",
    "fsuid",
    "ouid",
    "oauid",
    "old-auid",
    "iuid",
    "id",
    "inode_uid",
    "sauid",
    "obj_uid",
];

const GID_FIELD_NAMES: [&str; 9] = [
    "obj_gid",
    "gid",
    "egid",
    "sgid",
    "fsgid",
    "ogid",
    "igid",
    "inode_gid",
    "new_gid",
];

const CAP_BITMAP_FIELD_NAMES: [&str; 19] = [
    "cap_pi", "cap_pe", "cap_pp", "cap_pa", "cap_fi", "cap_fp", "fp", "fi", "old_pp", "old_pi",
    "old_pe", "old_pa", "new_pp", "new_pi", "new_pe", "pp", "pi", "pe", "pa",
];

const PERM_FIELD_NAMES: [&str; 2] = ["perm", "perm_mask"];

// Those are the equivalent of `AUPARSE_TYPE_SUCCESS` fields
const RESULT_FIELD_NAMES: [&str; 2] = ["res", "result"];

const SIGNAL_FIELD_NAMES: [&str; 2] = ["sig", "sigev_signo"];

pub enum FieldType {
    Msg,
    Exit,
    Escaped,
    Uid,
    Gid,
    CapabilityBitmap,
    SocketAddr,
    Perm,
    Result,
    Proctitle,
    Mode,
    Signal,
    List,
    // auparse does not interpet this field type,
    // their `AUPARSE_TYPE_SUCCESS` is used for `res` and `result` fields
    Success,
    Errno,
}

impl FieldType {
    // TODO: interpret a[[:digit:]+]\[.*\]
    pub fn resolve(field_name: &str) -> Option<Self> {
        if field_name == "msg" {
            return Some(Self::Msg);
        }

        if field_name == "exit" {
            return Some(Self::Exit);
        }

        if field_name == "saddr" {
            return Some(Self::SocketAddr);
        }

        if field_name == "proctitle" {
            return Some(Self::Proctitle);
        }

        if field_name == "mode" {
            return Some(Self::Mode);
        }

        if field_name == "list" {
            return Some(Self::List);
        }

        if field_name == "success" {
            return Some(Self::Success);
        }

        if field_name == "errno" {
            return Some(Self::Errno);
        }

        if ESCAPED_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Escaped);
        }

        if UID_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Uid);
        }

        if GID_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Gid);
        }

        if CAP_BITMAP_FIELD_NAMES.contains(&field_name) {
            return Some(Self::CapabilityBitmap);
        }

        if PERM_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Perm);
        }

        if RESULT_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Result);
        }

        if SIGNAL_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Signal);
        }

        None
    }
}
