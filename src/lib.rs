use std::{collections::BTreeMap, str::FromStr};

use parser::{ParserError, RawAuditdRecord};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

mod parser;
mod utils;

// TODO: implement an interpret to convert hexadecimal values into human-readable
// format, as `ausearch --interpret` does
// Example the `arch` field in https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-understanding_audit_log_files#sec-Understanding_Audit_Log_Files
// Create an InterpretedAuditdRecord that transforms an AuditdRecord into a human-readable format

// TODO: create an interpreted AuditdRecord that takes enrichment and replaces the raw fields with the enrichment?
//
// Or maybe we should have a RawAuditd record

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditdRecord {
    pub record_type: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,

    /// Record identifier
    pub id: u64,

    pub fields: BTreeMap<String, FieldValue>,

    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub enrichment: Option<BTreeMap<String, FieldValue>>,
}

// TODO: add an array variant for things like `grantors=pam_unix,pam_permit,pam_time`
// TODO: add a null variant for things like `hostname=?`
// TODO: add hexadecimal variant? That hexadecimal should be decoded or leaved as-is? Maybe
// we could interpret it in the interpret mode..?
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum FieldValue {
    Integer(u64),
    String(String),
    // TODO: use btreemap instead of BTreeMap? or use something like serde_json::Map type alias declared in this crate?
    Map(BTreeMap<String, FieldValue>),
}

impl From<&str> for FieldValue {
    fn from(s: &str) -> Self {
        FieldValue::String(s.to_string())
    }
}
impl From<String> for FieldValue {
    fn from(s: String) -> Self {
        FieldValue::String(s)
    }
}

impl From<u64> for FieldValue {
    fn from(i: u64) -> Self {
        FieldValue::Integer(i)
    }
}

impl From<BTreeMap<String, FieldValue>> for FieldValue {
    fn from(map: BTreeMap<String, FieldValue>) -> Self {
        FieldValue::Map(map)
    }
}

impl FromStr for AuditdRecord {
    // TODO: use thiserror instead of anyhow (or use snafu)
    type Err = ParserError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let raw_record = parser::parse_record(input)?;
        Ok(Self::from(raw_record))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: create a test that adds trailing data to the record, so `all_consuming` of `parse_record` fails

    // TODO: create unit tests for each of the parsers.

    // TODO: add a test where one of the fields starts by a number but ends with chars, for example `pid=123abc`,
    // so we can test that the `parse_unquoted_value` parser does not parse partially as an integer

    // TODO: snapshot testing with rstest cases, read cases from a file or
    // have it hardcoded in this file?
    // Those should be integration tests
    #[test]
    fn parse() {
        let line = "type=USER_ACCT msg=audit(1725039526.208:52): pid=580903 uid=1000 auid=1000 ses=2 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct=\"jorge\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/1 res=success'\u{1d}UID=\"jorge\" AUID=\"jorge\"";

        assert!(parser::parse_record(line).is_ok());
    }

    #[test]
    fn test_system_shutdown() {
        let line = "type=SYSTEM_SHUTDOWN msg=audit(1725041662.447:172): pid=834299 uid=0 auid=4294967295 ses=4294967295 msg=' comm=\"systemd-update-utmp\" exe=\"/usr/lib/systemd/systemd-update-utmp\" hostname=? addr=? terminal=? res=success'";
        assert!(parser::parse_record(line).is_ok());
    }
}
