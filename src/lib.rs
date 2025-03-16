use std::{collections::HashMap, str::FromStr};

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

    pub fields: HashMap<String, FieldValue>,

    pub enrichment: Option<HashMap<String, FieldValue>>,
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
    // TODO: use btreemap instead of hashmap? or use something like serde_json::Map type alias declared in this crate?
    Map(HashMap<String, FieldValue>),
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

impl From<HashMap<String, FieldValue>> for FieldValue {
    fn from(map: HashMap<String, FieldValue>) -> Self {
        FieldValue::Map(map)
    }
}

impl FromStr for AuditdRecord {
    // TODO: use thiserror instead of anyhow (or use snafu)
    type Err = anyhow::Error;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parser::parse_record(input)
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
}
