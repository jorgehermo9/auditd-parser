use super::constants;

pub enum FieldType {
    Escaped,
    Map,
}

impl FieldType {
    pub fn resolve(field_name: &str) -> Option<Self> {
        if field_name == "msg" {
            return Some(Self::Map);
        }

        if constants::ESCAPED_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Escaped);
        }

        None
    }
}
