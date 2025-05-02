use std::collections::BTreeMap;

use nom::{Parser, combinator::all_consuming};

use crate::{
    AuditdRecord, FieldValue,
    parser::{self, RawAuditdRecord},
    record::NestedFieldValue,
};

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
    match field_name {
        "msg" => interpret_msg_field(field_value),
        _ => FieldValue::String(field_value),
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
    let nested_field_value_map: BTreeMap<String, NestedFieldValue> = key_value_list
        .into_iter()
        // TODO: should we call interpret_field_value for nested fields inside the msg field?
        .map(|(key, val)| (key, NestedFieldValue::String(val)))
        .collect();

    FieldValue::Map(nested_field_value_map)
}
