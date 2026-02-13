use super::arch::AuditArch;

mod tables;

pub fn resolve_syscall_name(arch: AuditArch, syscall_number: u64) -> Option<&'static str> {
    let table = match arch {
        AuditArch::X86_64 => &*tables::X86_64_TABLE,
        // AArch64 is the same as ARM64
        AuditArch::AARCH64 => &*tables::ARM_64_TABLE,
        // Unsupported architecture
        _ => return None,
    };

    table.get(&syscall_number).map(|name| *name)
}
