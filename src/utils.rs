use nom::IResult;

/// Parser that consumes all of its input and returns it as-is.
///
/// This funcion always succeeds.
#[allow(clippy::unnecessary_wraps)]
pub fn burp(input: &str) -> IResult<&str, &str> {
    Ok(("", input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_burp() {
        assert_eq!(burp("hello"), Ok(("", "hello")));
    }
}
