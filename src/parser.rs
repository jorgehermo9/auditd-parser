use body::parse_body;
use header::parse_header;
use nom::{Finish, Parser, combinator::all_consuming};

use crate::AuditdRecord;

mod body;
mod header;

pub fn parse_record(input: &str) -> Result<AuditdRecord, anyhow::Error> {
    all_consuming(
        (parse_header, parse_body).map(|(header, body)| AuditdRecord {
            record_type: header.record_type,
            timestamp: header.audit_msg.timestamp,
            id: header.audit_msg.id,
            fields: body.fields,
            // TODO: we should lowercase the enrichment keys? Or leave it as is in a
            // `RawAuditdRecord` and then have a `AuditdRecord` that merges enrichment and fields
            enrichment: body.enrichment,
        }),
    )
    .parse(input)
    .finish()
    .map(|(_, record)| record)
    .map_err(|err| anyhow::anyhow!(err.to_string()))
}
