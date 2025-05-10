use super::constants;

pub enum FieldType {
    Escaped,
    // Change to `MaybeMap`?
    Msg,
    Uid,
    Gid,
}

impl FieldType {
    pub fn resolve(field_name: &str) -> Option<Self> {
        if field_name == "msg" {
            return Some(Self::Msg);
        }

        if constants::ESCAPED_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Escaped);
        }

        if constants::UID_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Uid);
        }

        if constants::GID_FIELD_NAMES.contains(&field_name) {
            return Some(Self::Gid);
        }

        None
    }
}
