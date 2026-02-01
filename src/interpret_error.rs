use thiserror::Error;

/// Error type for field interpretation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InterpretError {
    /// Failed to interpret a field value in strict mode.
    #[error("failed to interpret field '{field_name}' with value '{field_value}' in record type '{record_type}'")]
    UnknownValue {
        record_type: String,
        field_name: String,
        field_value: String,
    },
}

impl InterpretError {
    /// Creates a new interpretation error for an unknown value.
    pub fn unknown_value(
        record_type: impl Into<String>,
        field_name: impl Into<String>,
        field_value: impl Into<String>,
    ) -> Self {
        Self::UnknownValue {
            record_type: record_type.into(),
            field_name: field_name.into(),
            field_value: field_value.into(),
        }
    }
}
