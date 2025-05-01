use std::collections::BTreeMap;

use body::parse_body;
use header::parse_header;
use nom::{Finish, Parser};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod body;
mod header;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAuditdRecord {
    pub record_type: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,

    /// Record identifier
    pub id: u64,

    pub fields: BTreeMap<String, String>,

    pub enrichment: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ParserError {
    #[error("parsing error: {0}")]
    Parse(String),
}

pub fn parse_record(input: &str) -> Result<RawAuditdRecord, ParserError> {
    (parse_header, parse_body)
        .map(|(header, body)| RawAuditdRecord {
            record_type: header.record_type,
            timestamp: header.audit_msg.timestamp,
            id: header.audit_msg.id,
            fields: body.fields,
            // TODO: we should lowercase the enrichment keys? Or leave it as is in a
            // `RawAuditdRecord` and then have a `AuditdRecord` that merges enrichment and fields
            enrichment: body.enrichment,
        })
        .parse(input)
        .finish()
        .map(|(_, record)| record)
        .map_err(|err| ParserError::Parse(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use body::ENRICHMENT_SEPARATOR;
    use rstest::rstest;
    use std::collections::BTreeMap;

    #[rstest]
    #[case::unenriched("type=foo msg=audit(1234.567:89): key1=value1 key2=value2",
        RawAuditdRecord {
            record_type: "foo".into(),
            timestamp: 1_234_567,
            id: 89,
            fields: BTreeMap::from([("key1".into(), "value1".into()), ("key2".into(), "value2".into())]),
            enrichment: None,
        }
    )]
    #[case::enriched(&format!("type=foo msg=audit(1234.567:89): key1=value1 key2=value2{ENRICHMENT_SEPARATOR}enriched_key=enriched_value"),
        RawAuditdRecord {
            record_type: "foo".into(),
            timestamp: 1_234_567,
            id: 89,
            fields: BTreeMap::from([("key1".into(), "value1".into()), ("key2".into(), "value2".into())]),
            enrichment: Some(BTreeMap::from([("enriched_key".into(), "enriched_value".into())])),
        }
    )]
    fn test_parse_record(#[case] input: &str, #[case] expected: RawAuditdRecord) {
        assert_eq!(parse_record(input).unwrap(), expected);
    }

    #[rstest]
    #[case::invalid_header("foo msg=audit(1234.567:89) key1=value1")]
    #[case::invalid_body("type=foo msg=audit(1234.567:89): bar")]
    #[case::trailing_data("type=foo msg=audit(1234.567:89): key1=value1 key2=value2 foo")]
    #[case::empty("")]
    fn test_parse_record_fails(#[case] input: &str) {
        assert!(parse_record(input).is_err());
    }
}
