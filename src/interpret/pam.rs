// [Linux Pluggable Authentication Modules (PAM)](https://en.wikipedia.org/wiki/Linux_PAM)
// Interpreting inspired in the Linux PAM implementation
// https://github.com/linux-pam/linux-pam
//
// Audit logging can be found [here](https://github.com/linux-pam/linux-pam/blob/07f1d987466b33780c7147d9d55e1a52425b5005/libpam/pam_audit.c)
// and [here](https://github.com/linux-pam/linux-pam/blob/07f1d987466b33780c7147d9d55e1a52425b5005/libpam/pam_audit.c#L28)
//

pub fn parse_grantors(grantors: &str) -> Vec<&str> {
    // Grantors are separated by a comma
    // Ref: https://github.com/linux-pam/linux-pam/blob/ff030568bb68c7f0fa3253ffc4344035ecfed960/libpam/pam_audit.c#L90

    if grantors.is_empty() {
        return vec![];
    }

    grantors.split(',').collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("user1,user2,user3", vec!["user1", "user2", "user3"])]
    #[case("user1", vec!["user1"])]
    #[case("user1, user2", vec!["user1", " user2"])]
    #[case("", vec![])]
    fn test_parse_grantors(#[case] input: &str, #[case] expected: Vec<&str>) {
        let result = parse_grantors(input);
        assert_eq!(result, expected);
    }
}
