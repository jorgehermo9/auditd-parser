// Ref: https://github.com/linux-audit/audit-userspace/blob/747f67994b933fd70deed7d6f7cb0c40601f5bd1/auparse/interpret.c#L1000
pub fn parse_proctitle(bytes: &[u8]) -> String {
    // Proctitle arguments are null-byte separated
    dbg!(&bytes);
    bytes
        .split(|&b| b == 0)
        .map(|arg| String::from_utf8_lossy(arg).to_string())
        .collect::<Vec<String>>()
        .join(" ")
}
