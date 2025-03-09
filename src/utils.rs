use nom::IResult;

/// Parser that consumes all of its input and returns it as-is.
///
/// This funcion always succeeds.
pub fn burp(input: &str) -> IResult<&str, &str> {
    Ok(("", input))
}
