use std::collections::BTreeMap;

use field_type::FieldType;
use nom::{Parser, combinator::all_consuming};

use crate::{
    AuditdRecord, FieldValue,
    parser::{self, RawAuditdRecord},
};

mod constants;
mod field_type;

impl From<RawAuditdRecord> for AuditdRecord {
    // TODO: implement this propertly. We should interpret the field names
    // from the raw audit record to parse the auditd fields propertly.
    // Doing type checking and etc
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
    let nested_field_value_map: BTreeMap<String, String> = key_value_list
        .into_iter()
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::hex_encoded("666f6f", FieldValue::String("foo".to_string()))]
    #[case::not_encoded_fallback_to_input("foo", FieldValue::String("foo".to_string()))]
    #[case::hex_encoded_with_trailing_data_fallback_to_input("666f6fbar", FieldValue::String("666f6fbar".to_string()))]
    fn test_interpret_escaped_field(#[case] input: &str, #[case] expected: FieldValue) {
        let result = interpret_escaped_field(input.to_string());
        assert_eq!(result, expected);
    }
}
