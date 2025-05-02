mod interpret;
mod parser;
mod record;
pub use record::AuditdRecord;
pub use record::FieldValue;

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: create a test that adds trailing data to the record, so `all_consuming` of `parse_record` fails
    #[test]
    fn parse() {
        let line = "type=USER_ACCT msg=audit(1725039526.208:52): pid=580903 uid=1000 auid=1000 ses=2 msg='op=PAM:accounting grantors=pam_unix,pam_permit,pam_time acct=\"jorge\" exe=\"/usr/bin/sudo\" hostname=? addr=? terminal=/dev/pts/1 res=success'\u{1d}UID=\"jorge\" AUID=\"jorge\"";

        assert!(parser::parse_record(line).is_ok());
    }

    #[test]
    fn test_system_shutdown() {
        let line = "type=SYSTEM_SHUTDOWN msg=audit(1725041662.447:172): pid=834299 uid=0 auid=4294967295 ses=4294967295 msg=' comm=\"systemd-update-utmp\" exe=\"/usr/lib/systemd/systemd-update-utmp\" hostname=? addr=? terminal=? res=success'";
        assert!(parser::parse_record(line).is_ok());
    }
}
