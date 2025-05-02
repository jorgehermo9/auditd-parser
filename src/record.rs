use std::{collections::BTreeMap, str::FromStr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::parser::{self, ParserError};

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
