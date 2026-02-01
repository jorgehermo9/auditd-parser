/// Mode for handling unknown values during field interpretation.
///
/// When the parser encounters a field value that cannot be interpreted
/// (e.g., an unknown signal number or errno code), this mode determines
/// how the parser should handle it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum InterpretMode {
    /// Fail parsing and return an error if an unknown value is encountered.
    ///
    /// This ensures data type consistency by rejecting any records that
    /// contain values that cannot be interpreted.
    Strict,

    /// Omit the field as if it wasn't present when an unknown value is encountered.
    ///
    /// This provides a middle ground by maintaining data type consistency
    /// while still processing the rest of the record.
    Ignore,

    /// Fallback to the original field value when an unknown value is encountered.
    ///
    /// This is the default behavior and maintains backward compatibility.
    /// Note: This may result in heterogeneous data types for the same field.
    #[default]
    Fallback,
}

/// Configuration for field interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InterpretConfig {
    /// Mode for handling unknown values during field interpretation.
    pub mode: InterpretMode,
}

impl InterpretConfig {
    /// Creates a new configuration with the specified mode.
    pub fn new(mode: InterpretMode) -> Self {
        Self { mode }
    }

    /// Creates a configuration with strict mode enabled.
    pub fn strict() -> Self {
        Self::new(InterpretMode::Strict)
    }

    /// Creates a configuration with ignore mode enabled.
    pub fn ignore() -> Self {
        Self::new(InterpretMode::Ignore)
    }

    /// Creates a configuration with fallback mode enabled.
    pub fn fallback() -> Self {
        Self::new(InterpretMode::Fallback)
    }
}
