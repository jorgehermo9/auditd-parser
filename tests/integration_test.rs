use std::{fs, path::PathBuf};

use auditd_parser::{AuditdRecord, ParserError};
use erased_serde::Serialize;
use rstest::rstest;

#[rstest]
fn test_log_data(#[files("tests/data/**/*.log")] log_file: PathBuf) {
    let log_file_path = log_file.to_string_lossy().into_owned();
    let log_file_content = fs::read_to_string(log_file).unwrap();
    let logs = log_file_content
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line))
        .filter(|(_line_number, line)| !line.is_empty() && !line.starts_with('#'))
        .collect::<Vec<_>>();

    for (line_number, log) in logs {
        let maybe_record = log.parse::<AuditdRecord>();
        let location = format!("{log_file_path}:{line_number}");
        let log_identifier = get_log_identifier(log, &location);

        // Unwrap the Ok variant but leave the Err variant as-is
        let result: Box<dyn Serialize> = match maybe_record {
            Ok(record) => Box::new(record),
            Err(error) => Box::new(Err::<AuditdRecord, ParserError>(error)),
        };

        insta::with_settings!(
            {
                info => &log,
                description => location,
                snapshot_suffix => log_identifier,
            },
            {
                insta::assert_json_snapshot!(result);
            }
        );
    }
}

fn get_log_identifier(log: &str, location: &str) -> String {
    let log_md5 = md5::compute(format!("{log}{location}"));
    format!("{log_md5:x}")
}
