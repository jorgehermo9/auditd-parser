use crate::FieldValue;

pub fn into_string_to_field_value<T: ToString>(permissions: &[T]) -> FieldValue {
    permissions
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<String>>()
        .into()
}
