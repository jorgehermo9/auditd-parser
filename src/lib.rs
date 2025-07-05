mod interpret;
// TODO: remove this pub(crate) once refactor `interpret_key_value_field`
pub(crate) mod parser;
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

    #[test]
    fn test_node_field_parsing() {
        // Test record without node field
        let record_without_node = "type=USER_ACCT msg=audit(1725039526.208:52): pid=580903 uid=1000 auid=1000 ses=2";
        
        // Test record with node field
        let record_with_node = "node=server.example.com type=SYSCALL msg=audit(1725039526.208:52): pid=580903 uid=1000 auid=1000";
        
        // Parse record without node
        let parsed_without_node = record_without_node.parse::<AuditdRecord>().unwrap();
        assert_eq!(parsed_without_node.node, None);
        assert_eq!(parsed_without_node.record_type, "USER_ACCT");
        
        // Parse record with node
        let parsed_with_node = record_with_node.parse::<AuditdRecord>().unwrap();
        assert_eq!(parsed_with_node.node, Some("server.example.com".to_string()));
        assert_eq!(parsed_with_node.record_type, "SYSCALL");
        
        println!("✓ Node field parsing works correctly!");
    }

    #[test] 
    fn test_realistic_node_field_example() {
        // Test with a more realistic auditd record that includes node field
        let realistic_record = "node=audit-server.example.com type=SYSCALL msg=audit(1725039526.208:52): arch=c000003e syscall=59 success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=1000 gid=1000";
        
        let parsed = realistic_record.parse::<AuditdRecord>().unwrap();
        assert_eq!(parsed.node, Some("audit-server.example.com".to_string()));
        assert_eq!(parsed.record_type, "SYSCALL");
        assert_eq!(parsed.timestamp, 1725039526208);
        assert_eq!(parsed.id, 52);
        
        // Verify some of the fields were parsed correctly
        assert!(parsed.fields.contains_key("arch"));
        assert!(parsed.fields.contains_key("syscall"));
        assert!(parsed.fields.contains_key("pid"));
        
        println!("✓ Realistic node field example works!");
    }
}
