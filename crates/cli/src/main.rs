use auditd_parser::{AuditdRecord, InterpretConfig, InterpretMode};
use clap::{Parser, ValueEnum};
use std::io::{self, BufRead};

#[derive(Parser)]
#[command(name = "auditd-parser")]
#[command(about = "Parse auditd log records", long_about = None)]
struct Cli {
    /// Interpretation mode for handling unknown values
    #[arg(
        short = 'm',
        long = "mode",
        value_enum,
        default_value_t = InterpretModeArg::Fallback,
        help = "Interpretation mode:\n  - strict: Fail on unknown values\n  - ignore: Omit fields with unknown values\n  - fallback: Use original value (default)"
    )]
    mode: InterpretModeArg,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum InterpretModeArg {
    /// Fail parsing and return an error if an unknown value is encountered
    Strict,
    /// Omit the field as if it wasn't present when an unknown value is encountered
    Ignore,
    /// Fallback to the original field value when an unknown value is encountered
    Fallback,
}

impl From<InterpretModeArg> for InterpretMode {
    fn from(mode: InterpretModeArg) -> Self {
        match mode {
            InterpretModeArg::Strict => InterpretMode::Strict,
            InterpretModeArg::Ignore => InterpretMode::Ignore,
            InterpretModeArg::Fallback => InterpretMode::Fallback,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let config = InterpretConfig::new(cli.mode.into());

    let mut line = String::new();
    let stdin = io::stdin();
    stdin.lock().read_line(&mut line).unwrap();
    let line = line.trim();

    let auditd_record = AuditdRecord::parse_with_config(line, config);
    let result = match &auditd_record {
        Ok(record) => serde_json::to_string_pretty(&record).unwrap(),
        error @ Err(_) => serde_json::to_string_pretty(error).unwrap(),
    };
    println!("{result}")
}
