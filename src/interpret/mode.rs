use std::fmt::{self, Display, Formatter};

use crate::kernel_bindings;

// File mode constants are now imported from kernel headers via bindgen
// See kernel_bindings module for details
const FILE_TYPE_MASK: u32 = kernel_bindings::S_IFMT;
const ATTRIBUTES_MASK: u32 = kernel_bindings::S_ISUID | kernel_bindings::S_ISGID | kernel_bindings::S_ISVTX;
const USER_MASK: u32 = kernel_bindings::S_IRWXU;
const GROUP_MASK: u32 = kernel_bindings::S_IRWXG;
const OTHER_MASK: u32 = kernel_bindings::S_IRWXO;

// File type constants (these are the full values, we need to shift to compare)
const FILE_TYPE_SOCKET_MASK: u32 = kernel_bindings::S_IFSOCK;
const FILE_TYPE_SYMLINK_MASK: u32 = kernel_bindings::S_IFLNK;
const FILE_TYPE_REGULAR_FILE_MASK: u32 = kernel_bindings::S_IFREG;
const FILE_TYPE_BLOCK_DEVICE_MASK: u32 = kernel_bindings::S_IFBLK;
const FILE_TYPE_DIRECTORY_MASK: u32 = kernel_bindings::S_IFDIR;
const FILE_TYPE_CHAR_DEVICE_MASK: u32 = kernel_bindings::S_IFCHR;
const FILE_TYPE_FIFO_MASK: u32 = kernel_bindings::S_IFIFO;

// Attribute constants
const ATTRIBUTE_SETUID_MASK: u32 = kernel_bindings::S_ISUID;
const ATTRIBUTE_SETGID_MASK: u32 = kernel_bindings::S_ISGID;
const ATTRIBUTE_STICKY_MASK: u32 = kernel_bindings::S_ISVTX;

// Permission constants
const PERMISSION_READ_MASK_USER: u32 = kernel_bindings::S_IRUSR;
const PERMISSION_WRITE_MASK_USER: u32 = kernel_bindings::S_IWUSR;
const PERMISSION_EXEC_MASK_USER: u32 = kernel_bindings::S_IXUSR;
const PERMISSION_READ_MASK_GROUP: u32 = kernel_bindings::S_IRGRP;
const PERMISSION_WRITE_MASK_GROUP: u32 = kernel_bindings::S_IWGRP;
const PERMISSION_EXEC_MASK_GROUP: u32 = kernel_bindings::S_IXGRP;
const PERMISSION_READ_MASK_OTHER: u32 = kernel_bindings::S_IROTH;
const PERMISSION_WRITE_MASK_OTHER: u32 = kernel_bindings::S_IWOTH;
const PERMISSION_EXEC_MASK_OTHER: u32 = kernel_bindings::S_IXOTH;

#[derive(Debug, PartialEq)]
pub struct Mode {
    pub file_type: FileType,
    pub attributes: Vec<Attribute>,
    pub user: Vec<Permission>,
    pub group: Vec<Permission>,
    pub other: Vec<Permission>,
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    Socket,
    Symlink,
    RegularFile,
    BlockDevice,
    Directory,
    CharDevice,
    Fifo,
    Unknown,
}

impl Display for FileType {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Socket => write!(f, "socket"),
            FileType::Symlink => write!(f, "symlink"),
            FileType::RegularFile => write!(f, "regular-file"),
            FileType::BlockDevice => write!(f, "block-device"),
            FileType::Directory => write!(f, "directory"),
            FileType::CharDevice => write!(f, "char-device"),
            FileType::Fifo => write!(f, "fifo"),
            FileType::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Permission {
    Read,
    Write,
    Exec,
}

impl Display for Permission {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO: rwx or read, write, exec?
        match self {
            Permission::Read => write!(f, "read"),
            Permission::Write => write!(f, "write"),
            Permission::Exec => write!(f, "exec"),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum Attribute {
    Sticky,
    Setgid,
    Setuid,
}

impl Display for Attribute {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Attribute::Sticky => write!(f, "sticky"),
            Attribute::Setgid => write!(f, "setgid"),
            Attribute::Setuid => write!(f, "setuid"),
        }
    }
}

pub fn resolve_mode(mode: &str) -> Option<Mode> {
    let mode = u32::from_str_radix(mode, 8).ok()?;

    let file_type_bits = mode & FILE_TYPE_MASK;
    let attributes_bits = mode & ATTRIBUTES_MASK;

    Some(Mode {
        file_type: resolve_file_type(file_type_bits),
        attributes: resolve_attributes(attributes_bits),
        user: resolve_user_permissions(mode),
        group: resolve_group_permissions(mode),
        other: resolve_other_permissions(mode),
    })
}

fn resolve_attributes(attributes: u32) -> Vec<Attribute> {
    let mut result = vec![];

    if (attributes & ATTRIBUTE_STICKY_MASK) == ATTRIBUTE_STICKY_MASK {
        result.push(Attribute::Sticky);
    }

    if (attributes & ATTRIBUTE_SETGID_MASK) == ATTRIBUTE_SETGID_MASK {
        result.push(Attribute::Setgid);
    }

    if (attributes & ATTRIBUTE_SETUID_MASK) == ATTRIBUTE_SETUID_MASK {
        result.push(Attribute::Setuid);
    }

    result
}

fn resolve_user_permissions(mode: u32) -> Vec<Permission> {
    let mut result = vec![];

    if (mode & PERMISSION_READ_MASK_USER) == PERMISSION_READ_MASK_USER {
        result.push(Permission::Read);
    }

    if (mode & PERMISSION_WRITE_MASK_USER) == PERMISSION_WRITE_MASK_USER {
        result.push(Permission::Write);
    }

    if (mode & PERMISSION_EXEC_MASK_USER) == PERMISSION_EXEC_MASK_USER {
        result.push(Permission::Exec);
    }

    result
}

fn resolve_group_permissions(mode: u32) -> Vec<Permission> {
    let mut result = vec![];

    if (mode & PERMISSION_READ_MASK_GROUP) == PERMISSION_READ_MASK_GROUP {
        result.push(Permission::Read);
    }

    if (mode & PERMISSION_WRITE_MASK_GROUP) == PERMISSION_WRITE_MASK_GROUP {
        result.push(Permission::Write);
    }

    if (mode & PERMISSION_EXEC_MASK_GROUP) == PERMISSION_EXEC_MASK_GROUP {
        result.push(Permission::Exec);
    }

    result
}

fn resolve_other_permissions(mode: u32) -> Vec<Permission> {
    let mut result = vec![];

    if (mode & PERMISSION_READ_MASK_OTHER) == PERMISSION_READ_MASK_OTHER {
        result.push(Permission::Read);
    }

    if (mode & PERMISSION_WRITE_MASK_OTHER) == PERMISSION_WRITE_MASK_OTHER {
        result.push(Permission::Write);
    }

    if (mode & PERMISSION_EXEC_MASK_OTHER) == PERMISSION_EXEC_MASK_OTHER {
        result.push(Permission::Exec);
    }

    result
}

fn resolve_file_type(file_type: u32) -> FileType {
    match file_type {
        FILE_TYPE_SOCKET_MASK => FileType::Socket,
        FILE_TYPE_SYMLINK_MASK => FileType::Symlink,
        FILE_TYPE_REGULAR_FILE_MASK => FileType::RegularFile,
        FILE_TYPE_BLOCK_DEVICE_MASK => FileType::BlockDevice,
        FILE_TYPE_DIRECTORY_MASK => FileType::Directory,
        FILE_TYPE_CHAR_DEVICE_MASK => FileType::CharDevice,
        FILE_TYPE_FIFO_MASK => FileType::Fifo,
        _ => FileType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("0", Some(Mode {
        file_type: FileType::Unknown,
        attributes: vec![],
        user: vec![],
        group: vec![],
        other: vec![],
    }))]
    #[case("1", Some(Mode {
        file_type: FileType::Unknown,
        attributes: vec![],
        user: vec![],
        group: vec![],
        other: vec![Permission::Exec],
    }))]
    #[case("7", Some(Mode {
        file_type: FileType::Unknown,
        attributes: vec![],
        user: vec![],
        group: vec![],
        other: vec![Permission::Read, Permission::Write, Permission::Exec],
    }))]
    #[case("100000", Some(Mode {
        file_type: FileType::RegularFile,
        attributes: vec![],
        user: vec![],
        group: vec![],
        other: vec![],
    }))]
    #[case("100444", Some(Mode {
        file_type: FileType::RegularFile,
        attributes: vec![],
        user: vec![Permission::Read],
        group: vec![Permission::Read],
        other: vec![Permission::Read],
    }))]
    #[case("100777", Some(Mode {
        file_type: FileType::RegularFile,
        attributes: vec![],
        user: vec![Permission::Read, Permission::Write, Permission::Exec],
        group: vec![Permission::Read, Permission::Write, Permission::Exec],
        other: vec![Permission::Read, Permission::Write, Permission::Exec],
    }))]
    #[case("040644", Some(Mode {
        file_type: FileType::Directory,
        attributes: vec![],
        user: vec![Permission::Read, Permission::Write],
        group: vec![Permission::Read],
        other: vec![Permission::Read],
    }))]
    #[case("040755", Some(Mode {
        file_type: FileType::Directory,
        attributes: vec![],
        user: vec![Permission::Read, Permission::Write, Permission::Exec],
        group: vec![Permission::Read, Permission::Exec],
        other: vec![Permission::Read, Permission::Exec],
    }))]
    #[case("101644", Some(Mode {
        file_type: FileType::RegularFile,
        attributes: vec![Attribute::Sticky],
        user: vec![Permission::Read, Permission::Write],
        group: vec![Permission::Read],
        other: vec![Permission::Read],
    }))]
    #[case("147777", Some(Mode {
        file_type: FileType::Socket,
        attributes: vec![Attribute::Sticky, Attribute::Setgid, Attribute::Setuid],
        user: vec![Permission::Read, Permission::Write, Permission::Exec],
        group: vec![Permission::Read, Permission::Write, Permission::Exec],
        other: vec![Permission::Read, Permission::Write, Permission::Exec],
    }))]
    #[case::empty("", None)]
    fn test_resolve_mode(#[case] input: &str, #[case] expected: Option<Mode>) {
        let result = resolve_mode(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::none(0, vec![])]
    #[case::sticky(ATTRIBUTE_STICKY_MASK, vec![Attribute::Sticky])]
    #[case::setgid(ATTRIBUTE_SETGID_MASK, vec![Attribute::Setgid])]
    #[case::setuid(ATTRIBUTE_SETUID_MASK, vec![Attribute::Setuid])]
    #[case::all(ATTRIBUTE_STICKY_MASK | ATTRIBUTE_SETGID_MASK | ATTRIBUTE_SETUID_MASK, vec![Attribute::Sticky, Attribute::Setgid, Attribute::Setuid])]
    fn test_resolve_attributes(#[case] input: u32, #[case] expected: Vec<Attribute>) {
        let result = resolve_attributes(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::none(0, vec![])]
    #[case::read(PERMISSION_READ_MASK_USER, vec![Permission::Read])]
    #[case::write(PERMISSION_WRITE_MASK_USER, vec![Permission::Write])]
    #[case::exec(PERMISSION_EXEC_MASK_USER, vec![Permission::Exec])]
    #[case::read_write(PERMISSION_READ_MASK_USER | PERMISSION_WRITE_MASK_USER, vec![Permission::Read, Permission::Write])]
    #[case::read_exec(PERMISSION_READ_MASK_USER | PERMISSION_EXEC_MASK_USER, vec![Permission::Read, Permission::Exec])]
    #[case::write_exec(PERMISSION_WRITE_MASK_USER | PERMISSION_EXEC_MASK_USER, vec![Permission::Write, Permission::Exec])]
    #[case::all(PERMISSION_READ_MASK_USER | PERMISSION_WRITE_MASK_USER | PERMISSION_EXEC_MASK_USER, vec![Permission::Read, Permission::Write, Permission::Exec])]
    fn test_resolve_user_permissions(#[case] input: u32, #[case] expected: Vec<Permission>) {
        let result = resolve_user_permissions(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::none(0, vec![])]
    #[case::read(PERMISSION_READ_MASK_GROUP, vec![Permission::Read])]
    #[case::write(PERMISSION_WRITE_MASK_GROUP, vec![Permission::Write])]
    #[case::exec(PERMISSION_EXEC_MASK_GROUP, vec![Permission::Exec])]
    #[case::read_write(PERMISSION_READ_MASK_GROUP | PERMISSION_WRITE_MASK_GROUP, vec![Permission::Read, Permission::Write])]
    #[case::read_exec(PERMISSION_READ_MASK_GROUP | PERMISSION_EXEC_MASK_GROUP, vec![Permission::Read, Permission::Exec])]
    #[case::write_exec(PERMISSION_WRITE_MASK_GROUP | PERMISSION_EXEC_MASK_GROUP, vec![Permission::Write, Permission::Exec])]
    #[case::all(PERMISSION_READ_MASK_GROUP | PERMISSION_WRITE_MASK_GROUP | PERMISSION_EXEC_MASK_GROUP, vec![Permission::Read, Permission::Write, Permission::Exec])]
    fn test_resolve_group_permissions(#[case] input: u32, #[case] expected: Vec<Permission>) {
        let result = resolve_group_permissions(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::none(0, vec![])]
    #[case::read(PERMISSION_READ_MASK_OTHER, vec![Permission::Read])]
    #[case::write(PERMISSION_WRITE_MASK_OTHER, vec![Permission::Write])]
    #[case::exec(PERMISSION_EXEC_MASK_OTHER, vec![Permission::Exec])]
    #[case::read_write(PERMISSION_READ_MASK_OTHER | PERMISSION_WRITE_MASK_OTHER, vec![Permission::Read, Permission::Write])]
    #[case::read_exec(PERMISSION_READ_MASK_OTHER | PERMISSION_EXEC_MASK_OTHER, vec![Permission::Read, Permission::Exec])]
    #[case::write_exec(PERMISSION_WRITE_MASK_OTHER | PERMISSION_EXEC_MASK_OTHER, vec![Permission::Write, Permission::Exec])]
    #[case::all(PERMISSION_READ_MASK_OTHER | PERMISSION_WRITE_MASK_OTHER | PERMISSION_EXEC_MASK_OTHER, vec![Permission::Read, Permission::Write, Permission::Exec])]
    fn test_resolve_other_permissions(#[case] input: u32, #[case] expected: Vec<Permission>) {
        let result = resolve_other_permissions(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::unknown(0, FileType::Unknown)]
    #[case::unknown(0o150000, FileType::Unknown)]
    #[case::socket(FILE_TYPE_SOCKET_MASK, FileType::Socket)]
    #[case::symlink(FILE_TYPE_SYMLINK_MASK, FileType::Symlink)]
    #[case::regular_file(FILE_TYPE_REGULAR_FILE_MASK, FileType::RegularFile)]
    #[case::block_device(FILE_TYPE_BLOCK_DEVICE_MASK, FileType::BlockDevice)]
    #[case::directory(FILE_TYPE_DIRECTORY_MASK, FileType::Directory)]
    #[case::char_device(FILE_TYPE_CHAR_DEVICE_MASK, FileType::CharDevice)]
    #[case::fifo(FILE_TYPE_FIFO_MASK, FileType::Fifo)]
    fn test_resolve_file_type(#[case] input: u32, #[case] expected: FileType) {
        let result = resolve_file_type(input);
        assert_eq!(result, expected);
    }
}
