use auditd_parser::AuditdRecord;

const LOG_TEST_DATA: &[&str] = &[
    "audit-rhel6.log",
    "audit-rhel7.log",
    "audit-ubuntu14.log",
    "audit-ubuntu16.log",
    "audit-ubuntu17.log",
    "test2.log",
    "test3.log",
    "synthetic_perm.log", // TODO: https://github.com/jorgehermo9/auditd-parser/issues/41
];
const BASE_DIR: &str = "tests/testdata";

#[test]
fn test_log_data() {
    for log_file in LOG_TEST_DATA {
        let path = format!("{BASE_DIR}/{log_file}");
        let data = std::fs::read_to_string(path).unwrap();
        let logs = data
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect::<Vec<_>>();

        for log in logs {
            let record = log
                .parse::<AuditdRecord>()
                .unwrap_or_else(|_| panic!("Failed to parse record {log}"));
            let log_identifier = get_log_identifier(log);
            insta::with_settings!(
                {
                    info => &log,
                    snapshot_suffix => log_identifier,
                },
                {
                    insta::assert_json_snapshot!(record);
                }
            );
        }
    }
}

fn get_log_identifier(log: &str) -> String {
    let log_md5 = md5::compute(log);
    format!("{log_md5:x}")
}
