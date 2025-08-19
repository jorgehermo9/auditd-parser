use auditd_parser::AuditdRecord;
use std::io::{self, BufRead};

fn main() {
    let mut line = String::new();
    let stdin = io::stdin();
    stdin.lock().read_line(&mut line).unwrap();
    let auditd_record = line.parse::<AuditdRecord>();
    let result = match &auditd_record {
        Ok(record) => serde_json::to_string_pretty(&record).unwrap(),
        error @ Err(_) => serde_json::to_string_pretty(error).unwrap(),
    };
    println!("{result}")
}
