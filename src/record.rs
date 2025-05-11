use std::{collections::BTreeMap, str::FromStr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::parser::{self, ParserError};

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditdRecord {
    // TODO: rename `record_type` to `type`?
    pub record_type: String,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,

    /// Record identifier
    pub id: u64,

    // TODO: use index-ordered map?
    pub fields: BTreeMap<String, FieldValue>,

    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    // TODO: use index-ordered map?
    pub enrichment: Option<BTreeMap<String, FieldValue>>,
}

// TODO: add an array variant for things like `grantors=pam_unix,pam_permit,pam_time`
// TODO: add a null variant for things like `hostname=?`
// TODO: add hexadecimal variant? That hexadecimal should be decoded or leaved as-is? Maybe
// we could interpret it in the interpret mode..?
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum FieldValue {
    Number(Number),
    String(String),
    // TODO: Vec<String> or Vec<FieldValue>? is there any case
    // where we need an array of anything other than strings?
    Array(Vec<String>),
    // TODO: use index-ordered map?
    Map(BTreeMap<String, String>),
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(untagged))]
pub enum Number {
    UnsignedInteger(u64),
    SignedInteger(i64),
}

impl FromStr for AuditdRecord {
    // TODO: use thiserror instead of anyhow (or use snafu)
    type Err = ParserError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let raw_record = parser::parse_record(input)?;
        Ok(Self::from(raw_record))
    }
}
