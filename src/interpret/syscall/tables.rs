use std::{cell::LazyCell, collections::HashMap};

const COMMON_TABLE: &str = include_str!("tables/common/syscall.tbl");
const X86_TABLE: &str = include_str!("tables/x86/syscall_64.tbl");

const COMMON_64_BITS_ABIS: [&str; 2] = ["common", "64"];

pub const X86_64_TABLE: LazyCell<HashMap<u64, &'static str>> =
    LazyCell::new(|| get_syscall_table(X86_TABLE, &COMMON_64_BITS_ABIS));

// Arm64 table is based on the common table.
// See https://github.com/torvalds/linux/blob/b19a97d57c15643494ac8bfaaa35e3ee472d41da/arch/arm64/tools/syscall_64.tbl
pub const ARM_64_TABLE: LazyCell<HashMap<u64, &'static str>> =
    LazyCell::new(|| get_syscall_table(COMMON_TABLE, &COMMON_64_BITS_ABIS));

fn get_syscall_table(table: &'static str, abis: &[&str]) -> HashMap<u64, &'static str> {
    let mut syscall_map = HashMap::new();
    for line in table.lines() {
        // Skip comments and empty lines
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }

        // `parts[0]` is the syscall number, `parts[1]` is the ABI, and `parts[2]` is the syscall name
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue; // Invalid line format
        }

        let syscall_number: u64 = match parts[0].parse() {
            Ok(num) => num,
            Err(_) => continue, // Skip lines with invalid syscall numbers
        };

        let abi = parts[1];
        let syscall_name = parts[2];

        if abis.contains(&abi) {
            syscall_map.insert(syscall_number, syscall_name);
        }
    }
    syscall_map
}
