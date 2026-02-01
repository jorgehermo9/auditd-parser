use auditd_parser::{AuditdRecord, InterpretConfig};

#[test]
fn test_fallback_mode_unknown_signal() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=999";
    let config = InterpretConfig::fallback();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // In fallback mode, unknown signal should return the number
    assert!(record.fields.contains_key("sig"));
    match &record.fields["sig"] {
        auditd_parser::FieldValue::Number(n) => {
            assert_eq!(*n, auditd_parser::Number::UnsignedInteger(999));
        }
        _ => panic!("Expected Number variant"),
    }
}

#[test]
fn test_ignore_mode_unknown_signal() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=999 pid=123";
    let config = InterpretConfig::ignore();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // In ignore mode, unknown signal should be omitted
    assert!(!record.fields.contains_key("sig"));
    // But other fields should still be present
    assert!(record.fields.contains_key("pid"));
}

#[test]
fn test_strict_mode_unknown_signal() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=999";
    let config = InterpretConfig::strict();
    let result = AuditdRecord::parse_with_config(line, config);
    
    // In strict mode, unknown signal should cause an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        auditd_parser::AuditdParseError::Interpret(e) => {
            let err_str = e.to_string();
            assert!(err_str.contains("sig"));
            assert!(err_str.contains("999"));
        }
        _ => panic!("Expected InterpretError"),
    }
}

#[test]
fn test_fallback_mode_unknown_errno() {
    let line = "type=TEST msg=audit(1234567890.123:456): errno=999";
    let config = InterpretConfig::fallback();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // In fallback mode, unknown errno should return the number
    assert!(record.fields.contains_key("errno"));
    match &record.fields["errno"] {
        auditd_parser::FieldValue::Number(n) => {
            assert_eq!(*n, auditd_parser::Number::UnsignedInteger(999));
        }
        _ => panic!("Expected Number variant"),
    }
}

#[test]
fn test_ignore_mode_unknown_errno() {
    let line = "type=TEST msg=audit(1234567890.123:456): errno=999 pid=123";
    let config = InterpretConfig::ignore();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // In ignore mode, unknown errno should be omitted
    assert!(!record.fields.contains_key("errno"));
    // But other fields should still be present
    assert!(record.fields.contains_key("pid"));
}

#[test]
fn test_strict_mode_unknown_errno() {
    let line = "type=TEST msg=audit(1234567890.123:456): errno=999";
    let config = InterpretConfig::strict();
    let result = AuditdRecord::parse_with_config(line, config);
    
    // In strict mode, unknown errno should cause an error
    assert!(result.is_err());
}

#[test]
fn test_fallback_mode_unknown_audit_flag() {
    let line = "type=TEST msg=audit(1234567890.123:456): list=999";
    let config = InterpretConfig::fallback();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // In fallback mode, unknown list should return the number
    assert!(record.fields.contains_key("list"));
    match &record.fields["list"] {
        auditd_parser::FieldValue::Number(n) => {
            assert_eq!(*n, auditd_parser::Number::UnsignedInteger(999));
        }
        _ => panic!("Expected Number variant"),
    }
}

#[test]
fn test_ignore_mode_unknown_audit_flag() {
    let line = "type=TEST msg=audit(1234567890.123:456): list=999 pid=123";
    let config = InterpretConfig::ignore();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // In ignore mode, unknown list should be omitted
    assert!(!record.fields.contains_key("list"));
    // But other fields should still be present
    assert!(record.fields.contains_key("pid"));
}

#[test]
fn test_strict_mode_unknown_audit_flag() {
    let line = "type=TEST msg=audit(1234567890.123:456): list=999";
    let config = InterpretConfig::strict();
    let result = AuditdRecord::parse_with_config(line, config);
    
    // In strict mode, unknown list should cause an error
    assert!(result.is_err());
}

#[test]
fn test_fallback_mode_known_values() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=1 errno=1 list=0";
    let config = InterpretConfig::fallback();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // Known values should be interpreted correctly in all modes
    assert_eq!(record.fields["sig"], auditd_parser::FieldValue::String("SIGHUP".to_string()));
    assert_eq!(record.fields["errno"], auditd_parser::FieldValue::String("EPERM".to_string()));
    assert_eq!(record.fields["list"], auditd_parser::FieldValue::String("user".to_string()));
}

#[test]
fn test_strict_mode_known_values() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=1 errno=1 list=0";
    let config = InterpretConfig::strict();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // Known values should be interpreted correctly in all modes
    assert_eq!(record.fields["sig"], auditd_parser::FieldValue::String("SIGHUP".to_string()));
    assert_eq!(record.fields["errno"], auditd_parser::FieldValue::String("EPERM".to_string()));
    assert_eq!(record.fields["list"], auditd_parser::FieldValue::String("user".to_string()));
}

#[test]
fn test_ignore_mode_known_values() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=1 errno=1 list=0";
    let config = InterpretConfig::ignore();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // Known values should be interpreted correctly in all modes
    assert_eq!(record.fields["sig"], auditd_parser::FieldValue::String("SIGHUP".to_string()));
    assert_eq!(record.fields["errno"], auditd_parser::FieldValue::String("EPERM".to_string()));
    assert_eq!(record.fields["list"], auditd_parser::FieldValue::String("user".to_string()));
}

#[test]
fn test_default_mode_is_fallback() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=999";
    
    // Using FromStr (default mode)
    let record_default: AuditdRecord = line.parse().unwrap();
    
    // Using explicit fallback mode
    let record_fallback = AuditdRecord::parse_with_config(line, InterpretConfig::fallback()).unwrap();
    
    // They should be the same
    assert_eq!(record_default, record_fallback);
}

#[test]
fn test_fallback_mode_unparseable_field() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=not_a_number";
    let config = InterpretConfig::fallback();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // Unparseable values should fallback to string in fallback mode
    assert_eq!(record.fields["sig"], auditd_parser::FieldValue::String("not_a_number".to_string()));
}

#[test]
fn test_strict_mode_unparseable_field() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=not_a_number";
    let config = InterpretConfig::strict();
    let result = AuditdRecord::parse_with_config(line, config);
    
    // Unparseable values should cause error in strict mode
    assert!(result.is_err());
}

#[test]
fn test_ignore_mode_unparseable_field() {
    let line = "type=TEST msg=audit(1234567890.123:456): sig=not_a_number pid=123";
    let config = InterpretConfig::ignore();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // Unparseable values should be omitted in ignore mode
    assert!(!record.fields.contains_key("sig"));
    assert!(record.fields.contains_key("pid"));
}

#[test]
fn test_fallback_mode_unknown_arch() {
    let line = "type=TEST msg=audit(1234567890.123:456): arch=deadbeef";
    let config = InterpretConfig::fallback();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // Unknown arch should fallback to string
    assert_eq!(record.fields["arch"], auditd_parser::FieldValue::String("deadbeef".to_string()));
}

#[test]
fn test_strict_mode_unknown_arch() {
    let line = "type=TEST msg=audit(1234567890.123:456): arch=deadbeef";
    let config = InterpretConfig::strict();
    let result = AuditdRecord::parse_with_config(line, config);
    
    // Unknown arch should cause error in strict mode
    assert!(result.is_err());
}

#[test]
fn test_ignore_mode_unknown_arch() {
    let line = "type=TEST msg=audit(1234567890.123:456): arch=deadbeef pid=123";
    let config = InterpretConfig::ignore();
    let record = AuditdRecord::parse_with_config(line, config).unwrap();
    
    // Unknown arch should be omitted in ignore mode
    assert!(!record.fields.contains_key("arch"));
    assert!(record.fields.contains_key("pid"));
}
