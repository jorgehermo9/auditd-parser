use super::constants;

pub enum FieldType {
    // Change to `MaybeMap`?
    Msg,
    Exit,
    Escaped,
    Uid,
    Gid,
    CapabilityBitmap,
}

impl FieldType {
    pub fn resolve(field_name: &str) -> Option<Self> {
        if field_name == "msg" {
            return Some(Self::Msg);
        }

        if field_name == "exit" {
            return Some(Self::Exit);
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

        if constants::CAP_BITMAP_FIELD_NAMES.contains(&field_name) {
            return Some(Self::CapabilityBitmap);
        }

        None
    }
}
