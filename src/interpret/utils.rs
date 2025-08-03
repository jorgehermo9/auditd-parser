use crate::FieldValue;

pub fn into_string_array_to_field_value<T: ToString>(array: &[T]) -> FieldValue {
    array
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<String>>()
        .into()
}
