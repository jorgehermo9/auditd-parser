use nom::IResult;

/// Parser that simply consumes all of its input. It is useful for the last choice of an `alt` parser
/// to leave the input untouched.
///
/// This funcion always succeeds.
pub fn consume_all(input: &str) -> IResult<&str, &str> {
    Ok(("", input))
}
