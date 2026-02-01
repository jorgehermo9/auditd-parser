# auditd-parser

A Rust library for parsing and interpreting Linux auditd log records.

## Features

- Parse auditd log lines into structured data
- Interpret field values (e.g., convert signal numbers to names, resolve UIDs)
- Configurable interpretation modes for handling unknown values
- Serde support for serialization/deserialization
- CLI tool for parsing auditd logs

## Interpretation Modes

The parser supports three modes for handling unknown values during field interpretation:

- **Fallback Mode** (default): Falls back to the original value when an unknown value is encountered. This may result in heterogeneous data types for the same field but ensures all data is preserved.
- **Strict Mode**: Fails parsing and returns an error if an unknown value is encountered. This ensures data type consistency.
- **Ignore Mode**: Omits fields with unknown values as if they weren't present. This provides a middle ground between strict and fallback modes.

## Usage

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
auditd-parser = { version = "0.1", features = ["serde"] }
```

Basic usage with default (fallback) mode:

```rust
use auditd_parser::AuditdRecord;

let line = "type=USER_AUTH msg=audit(1234567890.123:456): pid=123 uid=0 sig=1";
let record: AuditdRecord = line.parse().unwrap();
```

Using different interpretation modes:

```rust
use auditd_parser::{AuditdRecord, InterpretConfig};

let line = "type=USER_AUTH msg=audit(1234567890.123:456): pid=123 uid=0 sig=999";

// Strict mode: fails on unknown values
let result = AuditdRecord::parse_with_config(line, InterpretConfig::strict());
assert!(result.is_err()); // sig=999 is unknown

// Ignore mode: omits unknown values
let record = AuditdRecord::parse_with_config(line, InterpretConfig::ignore()).unwrap();
assert!(!record.fields.contains_key("sig")); // Field is omitted

// Fallback mode: uses original value
let record = AuditdRecord::parse_with_config(line, InterpretConfig::fallback()).unwrap();
assert!(record.fields.contains_key("sig")); // Field contains numeric value
```

### CLI Tool

The CLI tool accepts a single line of auditd log on stdin and outputs JSON:

```bash
# Default (fallback) mode
echo 'type=USER_AUTH msg=audit(1234567890.123:456): sig=1' | cargo run --package cli

# Strict mode
echo 'type=USER_AUTH msg=audit(1234567890.123:456): sig=1' | cargo run --package cli -- --mode strict

# Ignore mode
echo 'type=USER_AUTH msg=audit(1234567890.123:456): sig=999' | cargo run --package cli -- --mode ignore
```

# TODOs
- [ ] Add tests
  - [x] parse_record unit tests
  - [x] Parser integration tests
    - Add a test for SYSTEM_SHUTDOWN logs, see https://github.com/linux-audit/audit-kernel/issues/169
  - [ ] Fuzz testing?
- [ ] justfile to run CI
- [ ] Clippy pedantic lints
- [ ] Add CI
- [ ] Add release workflow with `release-plz` crate
- [ ] Add documentation
- [x] CLI binary to read auditd logs? Or at least, as an example of how to use the library

# MSRV
`rustc 1.85`
