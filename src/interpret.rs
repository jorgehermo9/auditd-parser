use std::collections::BTreeMap;

use bytes::Bytes;
use field_type::FieldType;
use nom::{Parser, combinator::all_consuming};
use socket::SocketAddr;

use crate::{
    AuditdRecord, FieldValue,
    parser::{self, RawAuditdRecord},
    record::Number,
};

mod capability;
mod field_type;
mod socket;

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
                .map(|(key, val)| (key, FieldValue::String(val)))
                .collect()
        });

        Self {
            record_type: value.record_type,
            timestamp: value.timestamp,
            id: value.id,
            fields,
            enrichment,
        }
    }
}

fn interpret_field_value(_record_type: &str, field_name: &str, field_value: String) -> FieldValue {
    let Some(field_type) = FieldType::resolve(field_name) else {
        // Defaults to leave the field uninterpreted
        return FieldValue::String(field_value);
    };

    match field_type {
        FieldType::Escaped => interpret_escaped_field(field_value),
        FieldType::Msg => interpret_msg_field(field_value),
        FieldType::Uid | FieldType::Gid => interpret_unsigned_integer_field(field_value),
        FieldType::Exit => interpret_signed_integer_field(field_value),
        FieldType::CapabilityBitmap => interpret_cap_bitmap_field(field_value),
        FieldType::SocketAddr => interpret_socket_addr_field(field_value),
    }
}

fn interpret_msg_field(field_value: String) -> FieldValue {
    // TODO: fields inside msg should be interpreted aswell?
    let Ok((_, key_value_list)) =
        // TODO: maybe we should refactor this so this doesn't use parser module functions...
        all_consuming(parser::body::parse_key_value_list)
            .parse(field_value.as_str())
    else {
        return FieldValue::String(field_value);
    };
    // TODO: create a new parse_key_value_list here that returns NestedFieldValue itself...
    let nested_field_value_map = key_value_list
        .into_iter()
        .map(|(key, value)| (key, FieldValue::String(value)))
        // TODO: should we call interpret_field_value for nested fields inside the msg field?
        .collect();

    FieldValue::Map(nested_field_value_map)
}

// https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/lib/audit_logging.c#L103
fn interpret_escaped_field(field_value: String) -> FieldValue {
    // TODO handle `au_unescape` correctly (for example, see the parenthesis and (null))
    // https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L343
    let hex_decoded =
        hex::decode(&field_value).map(|bytes| String::from_utf8_lossy(&bytes).to_string());
    FieldValue::String(hex_decoded.unwrap_or(field_value))
}

fn interpret_unsigned_integer_field(field_value: String) -> FieldValue {
    field_value.parse().map_or_else(
        |_| FieldValue::String(field_value),
        |val| FieldValue::Number(Number::UnsignedInteger(val)),
    )
}

fn interpret_signed_integer_field(field_value: String) -> FieldValue {
    field_value.parse().map_or_else(
        |_| FieldValue::String(field_value),
        |val| FieldValue::Number(Number::SignedInteger(val)),
    )
}

fn interpret_cap_bitmap_field(field_value: String) -> FieldValue {
    // Capabilities are encoded as a 64-bit hexadecimal string
    let Ok(cap_bitmap) = u64::from_str_radix(&field_value, 16) else {
        return FieldValue::String(field_value);
    };

    let capabilities = capability::resolve_capability_bitmap(cap_bitmap);

    FieldValue::Array(capabilities)
}

fn interpret_socket_addr_field(field_value: String) -> FieldValue {
    let Ok(byte_vec) = hex::decode(&field_value) else {
        return FieldValue::String(field_value);
    };
    let bytes = Bytes::from(byte_vec);

    let Some(socket_address) = socket::parse_sockaddr(bytes) else {
        return FieldValue::String(field_value);
    };

    let mut map = BTreeMap::new();

    map.insert(
        "family".into(),
        FieldValue::String(socket_address.family().to_string()),
    );
    match socket_address {
        SocketAddr::Local(local_address) => {
            map.insert("path".into(), FieldValue::String(local_address.path));
        }
        SocketAddr::Inet(inet_address) => {
            map.insert(
                "address".into(),
                FieldValue::String(inet_address.to_string()),
            );
        }
        SocketAddr::Inet6(inet6_address) => {
            map.insert(
                "address".into(),
                FieldValue::String(inet6_address.to_string()),
            );
        }
        SocketAddr::Netlink(netlink_address) => {
            map.insert(
                "port_id".into(),
                FieldValue::Number(Number::UnsignedInteger(u64::from(netlink_address.port_id))),
            );
            map.insert(
                "groups".into(),
                FieldValue::Number(Number::UnsignedInteger(u64::from(netlink_address.groups))),
            );
        }
    }

    FieldValue::Map(map)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    // TODO: add tests for interpret_msg_field

    #[rstest]
    #[case::hex_encoded("666f6f", FieldValue::String("foo".to_string()))]
    #[case::not_encoded_fallbacks_to_input("foo", FieldValue::String("foo".to_string()))]
    #[case::hex_encoded_with_trailing_data_fallbacks_to_input("666f6fbar", FieldValue::String("666f6fbar".to_string()))]
    fn test_interpret_escaped_field(#[case] input: &str, #[case] expected: FieldValue) {
        let result = interpret_escaped_field(input.to_string());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::positive_integer("123", FieldValue::Number(Number::UnsignedInteger(123)))]
    #[case::negative_integer("-123", FieldValue::String("-123".to_string()))]
    #[case::not_integer_fallbacks_to_input("foo", FieldValue::String("foo".to_string()))]
    fn test_interpret_integer_field(#[case] input: &str, #[case] expected: FieldValue) {
        let result = interpret_unsigned_integer_field(input.to_string());
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::integer("123", FieldValue::Number(Number::SignedInteger(123)))]
    #[case::negative_integer("-123", FieldValue::Number(Number::SignedInteger(-123)))]
    #[case::not_integer_fallbacks_to_input("foo", FieldValue::String("foo".to_string()))]
    fn test_interpret_signed_integer_field(#[case] input: &str, #[case] expected: FieldValue) {
        let result = interpret_signed_integer_field(input.to_string());
        assert_eq!(result, expected);
    }

    // TODO: add tests for interpret_socket_addr_field.
    // Use https://docs.rs/maplit/latest/maplit/macro.btreemap.html as a test dependency
    // to create BTreeMaps in the test cases
}
