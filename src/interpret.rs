use std::collections::BTreeMap;

use bytes::Bytes;
use errno::Errno;
use field_type::FieldType;
use mac_label::MacLabel;
use nom::{Parser, combinator::all_consuming};
use signal::Signal;
use socket::SocketAddr;
use uid::Uid;

use crate::{
    AuditdRecord, FieldValue,
    parser::{self, RawAuditdRecord},
    record::Number,
};

mod arch;
mod audit_flag;
mod capability;
mod errno;
mod field_type;
mod mac_label;
mod mode;
mod null;
mod pam;
mod perm;
mod proctitle;
mod result;
mod signal;
mod socket;
mod success;
mod uid;
mod utils;

impl From<RawAuditdRecord> for AuditdRecord {
    fn from(value: RawAuditdRecord) -> Self {
        let fields = value
            .fields
            .into_iter()
            .map(|(field_name, field_value)| {
                let field_value =
                    interpret_field_value(&value.record_type, &field_name, field_value);

                (field_name, field_value)
            })
            .collect();

        let enrichment = value.enrichment.map(|enrichment| {
            enrichment
                .into_iter()
                .map(|(key, val)| (key, val.into()))
                .collect()
        });

        Self {
            record_type: value.record_type,
            timestamp: value.timestamp,
            id: value.id,
            node: value.node,
            fields,
            enrichment,
        }
    }
}

// Based on https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L3325
fn interpret_field_value(record_type: &str, field_name: &str, field_value: String) -> FieldValue {
    if null::is_null_value(&field_value) {
        return FieldValue::Null;
    }

    let Some(field_type) = FieldType::resolve(field_name) else {
        // Defaults to leave the field uninterpreted
        // TODO: should we default to `FieldValue::Escaped`?
        return field_value.into();
    };

    match field_type {
        FieldType::Escaped => interpret_escaped_field(field_value),
        FieldType::Msg => interpret_msg_field(record_type, field_value),
        FieldType::Uid | FieldType::Gid => interpret_uid_field(field_value),
        FieldType::Exit => interpret_exit_field(field_value),
        FieldType::CapabilityBitmap => interpret_cap_bitmap_field(field_value),
        FieldType::SocketAddr => interpret_socket_addr_field(field_value),
        FieldType::Perm => interpret_perm_field(field_value),
        FieldType::Result => interpret_result_field(&field_value),
        FieldType::Proctitle => interpret_proctitle_field(field_value),
        FieldType::Mode => interpret_mode_field(field_value),
        FieldType::Signal => interpret_signal_field(field_value),
        FieldType::List => interpret_list_field(field_value),
        FieldType::Success => interpret_success_field(field_value),
        FieldType::Errno => interpret_errno_field(field_value),
        FieldType::MacLabel => interpret_mac_label_field(field_value),
        FieldType::PAMGrantors => interpret_pam_grantors_field(&field_value),
    }
}

// TODO: move this to a msg.rs inside interpret module
fn interpret_msg_field(record_type: &str, field_value: String) -> FieldValue {
    let Ok((_, key_value_list)) =
        // TODO: maybe we should refactor this so this doesn't use parser module functions...
        all_consuming(parser::body::parse_key_value_list)
            .parse(field_value.as_str())
    else {
        return field_value.into();
    };
    let nested_field_value_map = key_value_list
        .into_iter()
        .map(|(key, value)| {
            // TODO: fields inside msg should be interpreted aswell?
            let interpreted_value = interpret_field_value(record_type, &key, value);
            (key, interpreted_value)
        })
        .collect::<BTreeMap<String, FieldValue>>();

    nested_field_value_map.into()
}

fn interpret_escaped_field(field_value: String) -> FieldValue {
    // TODO handle `au_unescape` correctly (for example, see the parenthesis and (null))
    // https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L343
    let hex_decoded =
        hex::decode(&field_value).map(|bytes| String::from_utf8_lossy(&bytes).to_string());
    hex_decoded.unwrap_or(field_value).into()
}

fn interpret_uid_field(field_value: String) -> FieldValue {
    let Ok(uid) = field_value.parse::<i64>() else {
        return field_value.into();
    };

    let uid = uid::resolve_uid(uid);

    match uid {
        Uid::Root => "root".to_string().into(),
        Uid::User(uid) => Number::SignedInteger(uid).into(),
        Uid::Unset => FieldValue::Null,
    }
}

fn interpret_exit_field(field_value: String) -> FieldValue {
    let Ok(exit_code) = field_value.parse::<i64>() else {
        return field_value.into();
    };
    Number::SignedInteger(exit_code).into()
}

fn interpret_cap_bitmap_field(field_value: String) -> FieldValue {
    // Capabilities are encoded as a 64-bit hexadecimal string
    let Ok(cap_bitmap) = u64::from_str_radix(&field_value, 16) else {
        return field_value.into();
    };

    let capabilities = capability::resolve_capability_bitmap(cap_bitmap);

    capabilities.into()
}

fn interpret_socket_addr_field(field_value: String) -> FieldValue {
    let Ok(byte_vec) = hex::decode(&field_value) else {
        return field_value.into();
    };
    let bytes = Bytes::from(byte_vec);

    let Some(socket_address) = socket::parse_sockaddr(bytes) else {
        return field_value.into();
    };

    let mut map = BTreeMap::new();

    map.insert("family".into(), socket_address.family().into());
    match socket_address {
        SocketAddr::Unix(unix_address) => {
            map.insert("path".into(), unix_address.path.into());
        }
        SocketAddr::Inet(inet_address) => {
            map.insert("address".into(), inet_address.to_string().into());
        }
        SocketAddr::Inet6(inet6_address) => {
            map.insert("address".into(), inet6_address.to_string().into());
        }
        SocketAddr::Netlink(netlink_address) => {
            map.insert(
                "port_id".into(),
                Number::from(u64::from(netlink_address.port_id)).into(),
            );
            map.insert(
                "multicast_groups_mask".into(),
                Number::from(u64::from(netlink_address.multicast_groups_mask)).into(),
            );
        }
    }

    map.into()
}

fn interpret_perm_field(field_value: String) -> FieldValue {
    // Perm is parsed as a long (usually 32 bits)
    // Ref: https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L1023
    let Ok(perm_mask) = field_value.parse::<u32>() else {
        return field_value.into();
    };

    let perms = perm::resolve_perm_mask(perm_mask);

    perms.into()
}

fn interpret_result_field(field_value: &str) -> FieldValue {
    result::resolve_result(field_value).to_string().into()
}

fn interpret_proctitle_field(field_value: String) -> FieldValue {
    let Ok(bytes) = hex::decode(&field_value) else {
        // If the field is not encoded as a hexstring, we assume that
        // it does not contain arguments separated by `\x00` and we return the field as is
        return field_value.into();
    };

    proctitle::parse_proctitle(&bytes).into()
}

fn interpret_mode_field(field_value: String) -> FieldValue {
    let Some(mode) = mode::resolve_mode(&field_value) else {
        // TODO: this default is kind of weird
        return field_value.into();
    };

    let mut map = BTreeMap::new();

    map.insert("file_type".into(), mode.file_type.to_string().into());
    map.insert(
        "attributes".into(),
        utils::into_string_array_to_field_value(&mode.attributes),
    );
    map.insert(
        "user".into(),
        utils::into_string_array_to_field_value(&mode.user),
    );
    map.insert(
        "group".into(),
        utils::into_string_array_to_field_value(&mode.group),
    );
    map.insert(
        "other".into(),
        utils::into_string_array_to_field_value(&mode.other),
    );

    map.into()
}

fn interpret_signal_field(field_value: String) -> FieldValue {
    let Ok(signal_number) = field_value.parse::<u64>() else {
        return field_value.into();
    };

    let Ok(signal) = Signal::try_from(signal_number) else {
        return Number::UnsignedInteger(signal_number).into();
    };

    signal.to_string().into()
}

fn interpret_list_field(field_value: String) -> FieldValue {
    let Ok(audit_flag_number) = field_value.parse::<u64>() else {
        return field_value.into();
    };

    let Some(audit_flag) = audit_flag::resolve_audit_flag(audit_flag_number) else {
        return Number::UnsignedInteger(audit_flag_number).into();
    };

    audit_flag.to_string().into()
}

fn interpret_success_field(field_value: String) -> FieldValue {
    let Some(success) = success::resolve_success(&field_value) else {
        return field_value.into();
    };

    success.into()
}

fn interpret_errno_field(field_value: String) -> FieldValue {
    let Ok(errno_number) = field_value.parse::<u64>() else {
        return field_value.into();
    };

    let Ok(errno) = Errno::try_from(errno_number) else {
        return Number::UnsignedInteger(errno_number).into();
    };

    errno.to_string().into()
}

fn interpret_mac_label_field(field_value: String) -> FieldValue {
    let Some(mac_label) = mac_label::resolve_mac_label(&field_value) else {
        return field_value.into();
    };

    let mut map = BTreeMap::new();

    map.insert("module".into(), mac_label.module().into());
    match mac_label {
        MacLabel::SELinux(context) => {
            map.insert("user".into(), context.user.into());
            map.insert("role".into(), context.role.into());
            map.insert("type".into(), context.r#type.into());

            if let Some(level) = context.level {
                let mut level_map = BTreeMap::new();
                level_map.insert("sensitivity".into(), level.sensitivity.into());
                if let Some(category) = level.category {
                    level_map.insert("category".into(), category.into());
                }
                map.insert("level".into(), level_map.into());
            }

            map.into()
        }
    }
}

fn interpret_pam_grantors_field(field_value: &str) -> FieldValue {
    let grantors = pam::parse_grantors(field_value);

    utils::into_string_array_to_field_value(&grantors)
}

#[cfg(test)]
mod tests {
    use maplit::btreemap;
    use rstest::rstest;

    use super::*;

    // TODO: add tests for interpret_msg_field
    //

    #[rstest]
    #[case::null("?", FieldValue::Null)]
    fn test_interpret_field_value(#[case] field_value: String, #[case] expected: FieldValue) {
        let result = interpret_field_value("test_type", "test_field_name", field_value);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::hex_encoded("666f6f","foo".into())]
    #[case::not_encoded_fallbacks_to_input("foo", "foo".into())]
    #[case::hex_encoded_with_trailing_data_fallbacks_to_input("666f6fbar", "666f6fbar".into())]
    fn test_interpret_escaped_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_escaped_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::root("0", "root".into())]
    #[case::unset("4294967295", FieldValue::Null)]
    #[case::unset_negative("-1", FieldValue::Null)]
    #[case::positive_integer("123", Number::SignedInteger(123).into())]
    #[case::negative_integer("-123", Number::SignedInteger(-123).into())]
    #[case::not_integer_fallbacks_to_input("foo", "foo".into())]
    fn test_interpret_uid_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_uid_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::zero("0", Number::SignedInteger(0).into())]
    #[case::positive_integer("123", Number::SignedInteger(123).into())]
    #[case::negative_integer("-123", Number::SignedInteger(-123).into())]
    #[case::not_integer_fallbacks_to_input("foo","foo".into())]
    fn test_interpret_exit_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_exit_field(input);
        assert_eq!(result, expected);
    }

    // TODO: add tests for interpret_socket_addr_field.
    // Use https://docs.rs/maplit/latest/maplit/macro.btreemap.html as a test dependency
    // to create BTreeMaps in the test cases
    #[rstest]
    #[case::af_unix("01002F7661722F72756E2F6E7363642F736F636B6574",
        btreemap!{
            "family".into() => "AF_UNIX".into(),
            "path".into() => "/var/run/nscd/socket".into(),
        }.into()
    )]
    #[case::af_inet("02000050A9FEA9FE",
        btreemap!{
            "family".into() => "AF_INET".into(),
            "address".into() => "169.254.169.254:80".into(),
        }.into()
    )]
    #[case::af_inet6("0A0000160000000020010DC8E0040001000000000000F00A00000000",
        btreemap!{
            "family".into() => "AF_INET6".into(),
            "address".into() => "[2001:dc8:e004:1::f00a]:22".into(),
        }.into()
    )]
    #[case::af_netlink("100000001000000001000000",
        btreemap!{
            "family".into() => "AF_NETLINK".into(),
            "port_id".into() => Number::UnsignedInteger(16).into(),
            "multicast_groups_mask".into() => Number::UnsignedInteger(1).into(),
        }.into()
    )]
    #[case::not_hexstring_fallbacks_to_input("foo", "foo".into())]
    #[case::incomplete_hexstring_fallbacks_to_input("012", "012".into())]
    #[case::parse_sockaddr_fail_fallbacks_to_input("FFFF0000", "FFFF0000".into())]
    fn test_interpret_socket_addr_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_socket_addr_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::all_zero("0", vec!["exec".into(), "write".into(), "read".into(), "attr".into()].into())]
    #[case::all_ones("15", vec!["exec".into(), "write".into(), "read".into(), "attr".into()].into())]
    #[case::exec("1", vec!["exec".into()].into())]
    #[case::write("2", vec!["write".into()].into())]
    #[case::read("4", vec!["read".into()].into())]
    #[case::attr("8", vec!["attr".into()].into())]
    #[case::exec_write("3", vec!["exec".into(), "write".into()].into())]
    #[case::read_attr("12", vec!["read".into(), "attr".into()].into())]
    #[case::exec_attr("9", vec!["exec".into(), "attr".into()].into())]
    #[case::write_read("6", vec!["write".into(), "read".into()].into())]
    #[case::max_u32("4294967295", vec!["exec".into(), "write".into(), "read".into(), "attr".into()].into())]
    #[case::none_perms("16", vec![].into())]
    #[case::resolve_perm_mask_fail_fallbacks_to_input("foo", "foo".into())]
    fn test_interpret_perm_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_perm_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::failed("0", "failed".into())]
    #[case::success("1", "success".into())]
    #[case::unset("2", "unset".into())]
    #[case::failed_string("failed", "failed".into())]
    #[case::success_string("success", "success".into())]
    #[case::foo("foo", "unset".into())]
    fn test_interpret_result_field(#[case] input: &str, #[case] expected: FieldValue) {
        let result = interpret_result_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::non_hexstring("foo", "foo".into())]
    #[case::hexstring("666f6f", "foo".into())]
    #[case::hexstring_with_args("666f6f00626172", "foo bar".into())]
    #[case::hexstring_with_multiple_args("666f6f006261720062617a", "foo bar baz".into())]
    #[case::non_utf8_hexstring("666f6f0062ff6172", "foo b�ar".into())]
    #[case::empty("", "".into())]
    fn test_interpret_proctitle_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_proctitle_field(input);
        assert_eq!(result, expected);
    }

    // TODO: add tests for interpret_mode_field
    //
    #[rstest]
    #[case("100644",
        btreemap!{
            "file_type".into() => "regular-file".into(),
            "attributes".into() => vec![].into(),
            "user".into() => vec!["read".into(), "write".into()].into(),
            "group".into() => vec!["read".into()].into(),
            "other".into() => vec!["read".into()].into(),
        }.into()
    )]
    #[case("7777",
        btreemap!{
            "file_type".into() => "unknown".into(),
            "attributes".into() => vec!["sticky".into(), "setgid".into(), "setuid".into()].into(),
            "user".into() => vec!["read".into(), "write".into(), "exec".into()].into(),
            "group".into() => vec!["read".into(), "write".into(), "exec".into()].into(),
            "other".into() => vec!["read".into(), "write".into(), "exec".into()].into(),
        }.into()
    )]
    #[case("100000",
        btreemap!{
            "file_type".into() => "regular-file".into(),
            "attributes".into() => vec![].into(),
            "user".into() => vec![].into(),
            "group".into() => vec![].into(),
            "other".into() => vec![].into(),
        }.into()
    )]
    #[case::empty("", "".into())]
    #[case::foo("foo", "foo".into())]
    fn test_interpret_mode_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_mode_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::foo("foo", "foo".into())]
    #[case::negative("-1", "-1".into())]
    #[case::zero("0", Number::UnsignedInteger(0).into())]
    #[case::sighup("1", "SIGHUP".into())]
    #[case::sigunused("32", "SIGUNUSED".into())]
    #[case::unknown("33", Number::UnsignedInteger(33).into())]
    fn test_interpret_signal_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_signal_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::foo("foo", "foo".into())]
    #[case::negative("-1", "-1".into())]
    #[case::user("0", "user".into())]
    #[case::task("1", "task".into())]
    #[case::entry("2", "entry".into())]
    #[case::watch("3", "watch".into())]
    #[case::exit("4", "exit".into())]
    #[case::exclude("5", "exclude".into())]
    #[case::filesystem("6", "filesystem".into())]
    #[case::io_uring_exit("7", "io-uring-exit".into())]
    #[case::unknown("8", Number::UnsignedInteger(8).into())]
    fn test_interpret_list_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_list_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::yes("yes", true.into())]
    #[case::no("no", false.into())]
    #[case::unknown("foo", "foo".into())]
    fn test_interpret_success_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_success_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::foo("foo", "foo".into())]
    #[case::zero("0", Number::UnsignedInteger(0).into())]
    #[case::eperm("1", "EPERM".into())]
    #[case::enoent("2", "ENOENT".into())]
    #[case::enomem("12", "ENOMEM".into())]
    fn test_interpret_errno_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_errno_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::selinux_minimal("user_u:role_r:type_t", btreemap!{
            "module".into() => "SELinux".into(),
            "user".into() => "user_u".into(),
            "role".into() => "role_r".into(),
            "type".into() => "type_t".into(),
        }.into()
    )]
    #[case::selinux_sensitivity("user_u:role_r:type_t:s0", btreemap!{
            "module".into() => "SELinux".into(),
            "user".into() => "user_u".into(),
            "role".into() => "role_r".into(),
            "type".into() => "type_t".into(),
            "level".into() => btreemap!{
                    "sensitivity".into() => "s0".into(),
                }.into(),
        }.into()
    )]
    #[case::selinux_sensitivity_and_category("user_u:role_r:type_t:s0:c1", btreemap!{
            "module".into() => "SELinux".into(),
            "user".into() => "user_u".into(),
            "role".into() => "role_r".into(),
            "type".into() => "type_t".into(),
            "level".into() => btreemap!{
                    "sensitivity".into() => "s0".into(),
                    "category".into() => "c1".into(),
                }.into(),
        }.into()
    )]
    #[case::not_a_mac_label("foo", "foo".into())]
    fn test_interpret_mac_label_field(#[case] input: String, #[case] expected: FieldValue) {
        let result = interpret_mac_label_field(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::no_grantors("", vec![].into())]
    #[case::single_grantor("user1", vec!["user1".into()].into())]
    #[case::multiple_grantors("user1,user2,user3", vec!["user1".into(), "user2".into(), "user3".into()].into())]
    #[case::multiple_grantors_with_spaces("user1, user2, user3", vec!["user1".into(), " user2".into(), " user3".into()].into())]
    #[case::empty_grantors("", vec![].into())]
    #[case::whitespace_grantors(" ", vec![" ".into()].into())]
    fn test_interpret_pam_grantors_field(#[case] input: &str, #[case] expected: FieldValue) {
        let result = interpret_pam_grantors_field(input);
        assert_eq!(result, expected);
    }
}
