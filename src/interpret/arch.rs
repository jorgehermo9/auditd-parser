#![allow(dead_code)]

use std::fmt::{self, Display, Formatter};

// ELF EM_ constants are extracted from https://github.com/torvalds/linux/blob/561c80369df0733ba0574882a1635287b20f9de2/include/uapi/linux/elf-em.h
const EM_NONE: u32 = 0;
const EM_M32: u32 = 1;
const EM_SPARC: u32 = 2;
const EM_386: u32 = 3;
const EM_68K: u32 = 4;
const EM_88K: u32 = 5;
const EM_486: u32 = 6;
const EM_860: u32 = 7;
const EM_MIPS: u32 = 8;
const EM_MIPS_RS3_LE: u32 = 10;
const EM_MIPS_RS4_BE: u32 = 10;
const EM_PARISC: u32 = 15;
const EM_SPARC32PLUS: u32 = 18;
const EM_PPC: u32 = 20;
const EM_PPC64: u32 = 21;
const EM_SPU: u32 = 23;
const EM_ARM: u32 = 40;
const EM_SH: u32 = 42;
const EM_SPARCV9: u32 = 43;
const EM_H8_300: u32 = 46;
const EM_IA_64: u32 = 50;
const EM_X86_64: u32 = 62;
const EM_S390: u32 = 22;
const EM_CRIS: u32 = 76;
const EM_M32R: u32 = 88;
const EM_MN10300: u32 = 89;
const EM_OPENRISC: u32 = 92;
const EM_ARCOMPACT: u32 = 93;
const EM_XTENSA: u32 = 94;
const EM_BLACKFIN: u32 = 106;
const EM_UNICORE: u32 = 110;
const EM_ALTERA_NIOS2: u32 = 113;
const EM_TI_C6000: u32 = 140;
const EM_HEXAGON: u32 = 164;
const EM_NDS32: u32 = 167;
const EM_AARCH64: u32 = 183;
const EM_TILEPRO: u32 = 188;
const EM_MICROBLAZE: u32 = 189;
const EM_TILEGX: u32 = 191;
const EM_ARCV2: u32 = 195;
const EM_RISCV: u32 = 243;
const EM_BPF: u32 = 247;
const EM_CSKY: u32 = 252;
const EM_LOONGARCH: u32 = 258;
const EM_FRV: u32 = 0x5441;
const EM_ALPHA: u32 = 0x9026;
const EM_CYGNUS_M32R: u32 = 0x9041;
const EM_S390_OLD: u32 = 0xA390;
const EM_CYGNUS_MN10300: u32 = 0xbeef;

// AUDIT_ARCH Constants are extracted from https://github.com/torvalds/linux/blob/561c80369df0733ba0574882a1635287b20f9de2/include/uapi/linux/audit.h#L387
const AUDIT_ARCH_CONVENTION_MASK: u32 = 0x3000_0000;
const AUDIT_ARCH_CONVENTION_MIPS64_N32: u32 = 0x2000_0000;
const AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
const AUDIT_ARCH_LE: u32 = 0x4000_0000;

const AUDIT_ARCH_AARCH64: u32 = EM_AARCH64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_ALPHA: u32 = EM_ALPHA | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_ARCOMPACT: u32 = EM_ARCOMPACT | AUDIT_ARCH_LE;
const AUDIT_ARCH_ARCOMPACTBE: u32 = EM_ARCOMPACT;
const AUDIT_ARCH_ARCV2: u32 = EM_ARCV2 | AUDIT_ARCH_LE;
const AUDIT_ARCH_ARCV2BE: u32 = EM_ARCV2;
const AUDIT_ARCH_ARM: u32 = EM_ARM | AUDIT_ARCH_LE;
// Typo in the original code, it is `AUDIT_ARCH_ARMEB` in the kernel
const AUDIT_ARCH_ARMBE: u32 = EM_ARM;
const AUDIT_ARCH_C6X: u32 = EM_TI_C6000 | AUDIT_ARCH_LE;
const AUDIT_ARCH_C6XBE: u32 = EM_TI_C6000;
const AUDIT_ARCH_CRIS: u32 = EM_CRIS | AUDIT_ARCH_LE;
const AUDIT_ARCH_CSKY: u32 = EM_CSKY | AUDIT_ARCH_LE;
const AUDIT_ARCH_FRV: u32 = EM_FRV;
const AUDIT_ARCH_H8300: u32 = EM_H8_300;
const AUDIT_ARCH_HEXAGON: u32 = EM_HEXAGON;
const AUDIT_ARCH_I386: u32 = EM_386 | AUDIT_ARCH_LE;
const AUDIT_ARCH_IA64: u32 = EM_IA_64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_M32R: u32 = EM_M32R;
const AUDIT_ARCH_M68K: u32 = EM_68K;
const AUDIT_ARCH_MICROBLAZE: u32 = EM_MICROBLAZE;
const AUDIT_ARCH_MIPS: u32 = EM_MIPS;
const AUDIT_ARCH_MIPSEL: u32 = EM_MIPS | AUDIT_ARCH_LE;
const AUDIT_ARCH_MIPS64: u32 = EM_MIPS | AUDIT_ARCH_64BIT;
const AUDIT_ARCH_MIPS64N32: u32 = EM_MIPS | AUDIT_ARCH_64BIT | AUDIT_ARCH_CONVENTION_MIPS64_N32;
const AUDIT_ARCH_MIPSEL64: u32 = EM_MIPS | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_MIPSEL64N32: u32 =
    EM_MIPS | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE | AUDIT_ARCH_CONVENTION_MIPS64_N32;
const AUDIT_ARCH_NDS32: u32 = EM_NDS32 | AUDIT_ARCH_LE;
const AUDIT_ARCH_NDS32BE: u32 = EM_NDS32;
const AUDIT_ARCH_NIOS2: u32 = EM_ALTERA_NIOS2 | AUDIT_ARCH_LE;
const AUDIT_ARCH_OPENRISC: u32 = EM_OPENRISC;
const AUDIT_ARCH_PARISC: u32 = EM_PARISC;
const AUDIT_ARCH_PARISC64: u32 = EM_PARISC | AUDIT_ARCH_64BIT;
const AUDIT_ARCH_PPC: u32 = EM_PPC;
const AUDIT_ARCH_PPC64: u32 = EM_PPC64 | AUDIT_ARCH_64BIT;
const AUDIT_ARCH_PPC64LE: u32 = EM_PPC64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_RISCV32: u32 = EM_RISCV | AUDIT_ARCH_LE;
const AUDIT_ARCH_RISCV64: u32 = EM_RISCV | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_S390: u32 = EM_S390;
const AUDIT_ARCH_S390X: u32 = EM_S390 | AUDIT_ARCH_64BIT;
const AUDIT_ARCH_SH: u32 = EM_SH;
const AUDIT_ARCH_SHEL: u32 = EM_SH | AUDIT_ARCH_LE;
const AUDIT_ARCH_SH64: u32 = EM_SH | AUDIT_ARCH_64BIT;
const AUDIT_ARCH_SHEL64: u32 = EM_SH | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_SPARC: u32 = EM_SPARC;
const AUDIT_ARCH_SPARC64: u32 = EM_SPARCV9 | AUDIT_ARCH_64BIT;
const AUDIT_ARCH_TILEGX: u32 = EM_TILEGX | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_TILEGX32: u32 = EM_TILEGX | AUDIT_ARCH_LE;
const AUDIT_ARCH_TILEPRO: u32 = EM_TILEPRO | AUDIT_ARCH_LE;
const AUDIT_ARCH_UNICORE: u32 = EM_UNICORE | AUDIT_ARCH_LE;
const AUDIT_ARCH_X86_64: u32 = EM_X86_64 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_XTENSA: u32 = EM_XTENSA;
const AUDIT_ARCH_LOONGARCH32: u32 = EM_LOONGARCH | AUDIT_ARCH_LE;
const AUDIT_ARCH_LOONGARCH64: u32 = EM_LOONGARCH | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditArch {
    AARCH64,
    ALPHA,
    ARCOMPACT,
    ARCOMPACTBE,
    ARCV2,
    ARCV2BE,
    ARM,
    ARMBE,
    C6X,
    C6XBE,
    CRIS,
    CSKY,
    FRV,
    H8300,
    HEXAGON,
    I386,
    IA64,
    M32R,
    M68K,
    MICROBLAZE,
    MIPS,
    MIPSEL,
    MIPS64,
    MIPS64N32,
    MIPSEL64,
    MIPSEL64N32,
    NDS32,
    NDS32BE,
    NIOS2,
    OPENRISC,
    PARISC,
    PARISC64,
    PPC,
    PPC64,
    PPC64LE,
    RISCV32,
    RISCV64,
    S390,
    S390X,
    SH,
    SHEL,
    SH64,
    SHEL64,
    SPARC,
    SPARC64,
    TILEGX,
    TILEGX32,
    TILEPRO,
    UNICORE,
    X86_64,
    XTENSA,
    LOONGARCH32,
    LOONGARCH64,
}

impl Display for AuditArch {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::I386 => write!(f, "i386"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl TryFrom<u32> for AuditArch {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        let arch = match value {
            AUDIT_ARCH_AARCH64 => AuditArch::AARCH64,
            AUDIT_ARCH_ALPHA => AuditArch::ALPHA,
            AUDIT_ARCH_ARCOMPACT => AuditArch::ARCOMPACT,
            AUDIT_ARCH_ARCOMPACTBE => AuditArch::ARCOMPACTBE,
            AUDIT_ARCH_ARCV2 => AuditArch::ARCV2,
            AUDIT_ARCH_ARCV2BE => AuditArch::ARCV2BE,
            AUDIT_ARCH_ARM => AuditArch::ARM,
            AUDIT_ARCH_ARMBE => AuditArch::ARMBE,
            AUDIT_ARCH_C6X => AuditArch::C6X,
            AUDIT_ARCH_C6XBE => AuditArch::C6XBE,
            AUDIT_ARCH_CRIS => AuditArch::CRIS,
            AUDIT_ARCH_CSKY => AuditArch::CSKY,
            AUDIT_ARCH_FRV => AuditArch::FRV,
            AUDIT_ARCH_H8300 => AuditArch::H8300,
            AUDIT_ARCH_HEXAGON => AuditArch::HEXAGON,
            AUDIT_ARCH_I386 => AuditArch::I386,
            AUDIT_ARCH_IA64 => AuditArch::IA64,
            AUDIT_ARCH_M32R => AuditArch::M32R,
            AUDIT_ARCH_M68K => AuditArch::M68K,
            AUDIT_ARCH_MICROBLAZE => AuditArch::MICROBLAZE,
            AUDIT_ARCH_MIPS => AuditArch::MIPS,
            AUDIT_ARCH_MIPSEL => AuditArch::MIPSEL,
            AUDIT_ARCH_MIPS64 => AuditArch::MIPS64,
            AUDIT_ARCH_MIPS64N32 => AuditArch::MIPS64N32,
            AUDIT_ARCH_MIPSEL64 => AuditArch::MIPSEL64,
            AUDIT_ARCH_MIPSEL64N32 => AuditArch::MIPSEL64N32,
            AUDIT_ARCH_NDS32 => AuditArch::NDS32,
            AUDIT_ARCH_NDS32BE => AuditArch::NDS32BE,
            AUDIT_ARCH_NIOS2 => AuditArch::NIOS2,
            AUDIT_ARCH_OPENRISC => AuditArch::OPENRISC,
            AUDIT_ARCH_PARISC => AuditArch::PARISC,
            AUDIT_ARCH_PARISC64 => AuditArch::PARISC64,
            AUDIT_ARCH_PPC => AuditArch::PPC,
            AUDIT_ARCH_PPC64 => AuditArch::PPC64,
            AUDIT_ARCH_PPC64LE => AuditArch::PPC64LE,
            AUDIT_ARCH_RISCV32 => AuditArch::RISCV32,
            AUDIT_ARCH_RISCV64 => AuditArch::RISCV64,
            AUDIT_ARCH_S390 => AuditArch::S390,
            AUDIT_ARCH_S390X => AuditArch::S390X,
            AUDIT_ARCH_SH => AuditArch::SH,
            AUDIT_ARCH_SHEL => AuditArch::SHEL,
            AUDIT_ARCH_SH64 => AuditArch::SH64,
            AUDIT_ARCH_SHEL64 => AuditArch::SHEL64,
            AUDIT_ARCH_SPARC => AuditArch::SPARC,
            AUDIT_ARCH_SPARC64 => AuditArch::SPARC64,
            AUDIT_ARCH_TILEGX => AuditArch::TILEGX,
            AUDIT_ARCH_TILEGX32 => AuditArch::TILEGX32,
            AUDIT_ARCH_TILEPRO => AuditArch::TILEPRO,
            AUDIT_ARCH_UNICORE => AuditArch::UNICORE,
            AUDIT_ARCH_X86_64 => AuditArch::X86_64,
            AUDIT_ARCH_XTENSA => AuditArch::XTENSA,
            AUDIT_ARCH_LOONGARCH32 => AuditArch::LOONGARCH32,
            AUDIT_ARCH_LOONGARCH64 => AuditArch::LOONGARCH64,
            _ => return Err(()),
        };
        Ok(arch)
    }
}
