use std::fmt::{self, Display, Formatter};

// Constants extracted from https://github.com/torvalds/linux/blob/5723cc3450bccf7f98f227b9723b5c9f6b3af1c5/include/uapi/linux/stat.h#L9
const FILE_TYPE_MASK: u32 = 0o170_000;
const ATTRIBUTES_MASK: u32 = 0o7_000;
const USER_MASK: u32 = 0o0700;
const GROUP_MASK: u32 = 0o0070;
const OTHER_MASK: u32 = 0o0007;

// See also https://man7.org/linux/man-pages/man2/stat.2.html
const FILE_TYPE_SOCKET_MASK: u32 = 0o14;
const FILE_TYPE_SYMLINK_MASK: u32 = 0o12;
const FILE_TYPE_REGULAR_FILE_MASK: u32 = 0o10;
const FILE_TYPE_BLOCK_DEVICE_MASK: u32 = 0o06;
const FILE_TYPE_DIRECTORY_MASK: u32 = 0o04;
const FILE_TYPE_CHAR_DEVICE_MASK: u32 = 0o02;
const FILE_TYPE_FIFO_MASK: u32 = 0o01;

const ATTRIBUTE_SETUID_MASK: u32 = 0o4;
const ATTRIBUTE_SETGID_MASK: u32 = 0o2;
const ATTRIBUTE_STICKY_MASK: u32 = 0o1;

const PERMISSION_READ_MASK: u32 = 0o4;
const PERMISSION_WRITE_MASK: u32 = 0o2;
const PERMISSION_EXEC_MASK: u32 = 0o1;

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
            FileType::RegularFile => write!(f, "regular file"),
            FileType::BlockDevice => write!(f, "block device"),
            FileType::Directory => write!(f, "directory"),
            FileType::CharDevice => write!(f, "char device"),
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
            Permission::Read => write!(f, "r"),
            Permission::Write => write!(f, "w"),
            Permission::Exec => write!(f, "x"),
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

    let file_type = (mode & FILE_TYPE_MASK) >> 12;
    let attributes = (mode & ATTRIBUTES_MASK) >> 9;
    let user = (mode & USER_MASK) >> 6;
    let group = (mode & GROUP_MASK) >> 3;
    let other = mode & OTHER_MASK;

    Some(Mode {
        file_type: resolve_file_type(file_type),
        attributes: resolve_attributes(attributes),
        user: resolve_permissions(user),
        group: resolve_permissions(group),
        other: resolve_permissions(other),
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

fn resolve_permissions(permissions: u32) -> Vec<Permission> {
    let mut result = vec![];

    if (permissions & PERMISSION_READ_MASK) == PERMISSION_READ_MASK {
        result.push(Permission::Read);
    }

    if (permissions & PERMISSION_WRITE_MASK) == PERMISSION_WRITE_MASK {
        result.push(Permission::Write);
    }

    if (permissions & PERMISSION_EXEC_MASK) == PERMISSION_EXEC_MASK {
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
    #[case::sticky(0o1, vec![Attribute::Sticky])]
    #[case::setgid(0o2, vec![Attribute::Setgid])]
    #[case::setuid(0o4, vec![Attribute::Setuid])]
    #[case::all(0o7, vec![Attribute::Sticky, Attribute::Setgid, Attribute::Setuid])]
    fn test_resolve_attributes(#[case] input: u32, #[case] expected: Vec<Attribute>) {
        let result = resolve_attributes(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::none(0, vec![])]
    #[case::read(0o4, vec![Permission::Read])]
    #[case::write(0o2, vec![Permission::Write])]
    #[case::exec(0o1, vec![Permission::Exec])]
    #[case::read_write(0o6, vec![Permission::Read, Permission::Write])]
    #[case::read_exec(0o5, vec![Permission::Read, Permission::Exec])]
    #[case::write_exec(0o3, vec![Permission::Write, Permission::Exec])]
    #[case::all(0o7, vec![Permission::Read, Permission::Write, Permission::Exec])]
    fn test_resolve_permissions(#[case] input: u32, #[case] expected: Vec<Permission>) {
        let result = resolve_permissions(input);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::unknown(0, FileType::Unknown)]
    #[case::socket(0o14, FileType::Socket)]
    #[case::symlink(0o12, FileType::Symlink)]
    #[case::regular_file(0o10, FileType::RegularFile)]
    #[case::block_device(0o6, FileType::BlockDevice)]
    #[case::directory(0o4, FileType::Directory)]
    #[case::char_device(0o2, FileType::CharDevice)]
    #[case::fifo(0o1, FileType::Fifo)]
    fn test_resolve_file_type(#[case] input: u32, #[case] expected: FileType) {
        let result = resolve_file_type(input);
        assert_eq!(result, expected);
    }
}
