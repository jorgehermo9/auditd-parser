use crate::{AuditdRecord, FieldValue, parser::RawAuditdRecord};

impl From<RawAuditdRecord> for AuditdRecord {
    // TODO: implement this propertly. We should interpret the field names
    // from the raw audit record to parse the auditd fields propertly.
    // Doing type checking and etc
    fn from(value: RawAuditdRecord) -> Self {
        let fields = value
            .fields
            .into_iter()
            .map(|(key, val)| (key, FieldValue::String(val)))
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
