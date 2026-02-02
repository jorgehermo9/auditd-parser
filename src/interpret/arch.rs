#![allow(dead_code)]

use std::fmt::{self, Display, Formatter};

use crate::kernel_bindings;

// ELF EM_ constants are now imported from kernel headers via bindgen
// See kernel_bindings module for details
const EM_NONE: u32 = kernel_bindings::EM_NONE;
const EM_M32: u32 = kernel_bindings::EM_M32;
const EM_SPARC: u32 = kernel_bindings::EM_SPARC;
const EM_386: u32 = kernel_bindings::EM_386;
const EM_68K: u32 = kernel_bindings::EM_68K;
const EM_88K: u32 = kernel_bindings::EM_88K;
const EM_486: u32 = kernel_bindings::EM_486;
const EM_860: u32 = kernel_bindings::EM_860;
const EM_MIPS: u32 = kernel_bindings::EM_MIPS;
const EM_MIPS_RS3_LE: u32 = kernel_bindings::EM_MIPS_RS3_LE;
const EM_MIPS_RS4_BE: u32 = kernel_bindings::EM_MIPS_RS4_BE;
const EM_PARISC: u32 = kernel_bindings::EM_PARISC;
const EM_SPARC32PLUS: u32 = kernel_bindings::EM_SPARC32PLUS;
const EM_PPC: u32 = kernel_bindings::EM_PPC;
const EM_PPC64: u32 = kernel_bindings::EM_PPC64;
const EM_SPU: u32 = kernel_bindings::EM_SPU;
const EM_ARM: u32 = kernel_bindings::EM_ARM;
const EM_SH: u32 = kernel_bindings::EM_SH;
const EM_SPARCV9: u32 = kernel_bindings::EM_SPARCV9;
const EM_H8_300: u32 = kernel_bindings::EM_H8_300;
const EM_IA_64: u32 = kernel_bindings::EM_IA_64;
const EM_X86_64: u32 = kernel_bindings::EM_X86_64;
const EM_S390: u32 = kernel_bindings::EM_S390;
const EM_CRIS: u32 = kernel_bindings::EM_CRIS;
const EM_M32R: u32 = kernel_bindings::EM_M32R;
const EM_MN10300: u32 = kernel_bindings::EM_MN10300;
const EM_OPENRISC: u32 = kernel_bindings::EM_OPENRISC;
const EM_ARCOMPACT: u32 = kernel_bindings::EM_ARCOMPACT;
const EM_XTENSA: u32 = kernel_bindings::EM_XTENSA;
const EM_BLACKFIN: u32 = kernel_bindings::EM_BLACKFIN;
const EM_UNICORE: u32 = kernel_bindings::EM_UNICORE;
const EM_ALTERA_NIOS2: u32 = kernel_bindings::EM_ALTERA_NIOS2;
const EM_TI_C6000: u32 = kernel_bindings::EM_TI_C6000;
const EM_HEXAGON: u32 = kernel_bindings::EM_HEXAGON;
const EM_NDS32: u32 = kernel_bindings::EM_NDS32;
const EM_AARCH64: u32 = kernel_bindings::EM_AARCH64;
const EM_TILEPRO: u32 = kernel_bindings::EM_TILEPRO;
const EM_MICROBLAZE: u32 = kernel_bindings::EM_MICROBLAZE;
const EM_TILEGX: u32 = kernel_bindings::EM_TILEGX;
const EM_ARCV2: u32 = kernel_bindings::EM_ARCV2;
const EM_RISCV: u32 = kernel_bindings::EM_RISCV;
const EM_BPF: u32 = kernel_bindings::EM_BPF;
const EM_CSKY: u32 = kernel_bindings::EM_CSKY;
const EM_LOONGARCH: u32 = kernel_bindings::EM_LOONGARCH;
const EM_FRV: u32 = kernel_bindings::EM_FRV;
const EM_ALPHA: u32 = kernel_bindings::EM_ALPHA;
const EM_CYGNUS_M32R: u32 = kernel_bindings::EM_CYGNUS_M32R;
const EM_S390_OLD: u32 = kernel_bindings::EM_S390_OLD;
const EM_CYGNUS_MN10300: u32 = kernel_bindings::EM_CYGNUS_MN10300;

// AUDIT_ARCH Constants are now imported from kernel headers via bindgen
const AUDIT_ARCH_CONVENTION_MASK: u32 = kernel_bindings::__AUDIT_ARCH_CONVENTION_MASK;
const AUDIT_ARCH_CONVENTION_MIPS64_N32: u32 = kernel_bindings::__AUDIT_ARCH_CONVENTION_MIPS64_N32;
const AUDIT_ARCH_64BIT: u32 = kernel_bindings::__AUDIT_ARCH_64BIT;
const AUDIT_ARCH_LE: u32 = kernel_bindings::__AUDIT_ARCH_LE;

const AUDIT_ARCH_AARCH64: u32 = kernel_bindings::AUDIT_ARCH_AARCH64;
const AUDIT_ARCH_ALPHA: u32 = kernel_bindings::AUDIT_ARCH_ALPHA;
const AUDIT_ARCH_ARCOMPACT: u32 = kernel_bindings::AUDIT_ARCH_ARCOMPACT;
const AUDIT_ARCH_ARCOMPACTBE: u32 = kernel_bindings::AUDIT_ARCH_ARCOMPACTBE;
const AUDIT_ARCH_ARCV2: u32 = kernel_bindings::AUDIT_ARCH_ARCV2;
const AUDIT_ARCH_ARCV2BE: u32 = kernel_bindings::AUDIT_ARCH_ARCV2BE;
const AUDIT_ARCH_ARM: u32 = kernel_bindings::AUDIT_ARCH_ARM;
// Typo in the original code, it is `AUDIT_ARCH_ARMEB` in the kernel
const AUDIT_ARCH_ARMBE: u32 = kernel_bindings::AUDIT_ARCH_ARMEB;
const AUDIT_ARCH_C6X: u32 = kernel_bindings::AUDIT_ARCH_C6X;
const AUDIT_ARCH_C6XBE: u32 = kernel_bindings::AUDIT_ARCH_C6XBE;
const AUDIT_ARCH_CRIS: u32 = kernel_bindings::AUDIT_ARCH_CRIS;
const AUDIT_ARCH_CSKY: u32 = kernel_bindings::AUDIT_ARCH_CSKY;
const AUDIT_ARCH_FRV: u32 = kernel_bindings::AUDIT_ARCH_FRV;
const AUDIT_ARCH_H8300: u32 = kernel_bindings::AUDIT_ARCH_H8300;
const AUDIT_ARCH_HEXAGON: u32 = kernel_bindings::AUDIT_ARCH_HEXAGON;
const AUDIT_ARCH_I386: u32 = kernel_bindings::AUDIT_ARCH_I386;
const AUDIT_ARCH_IA64: u32 = kernel_bindings::AUDIT_ARCH_IA64;
const AUDIT_ARCH_M32R: u32 = kernel_bindings::AUDIT_ARCH_M32R;
const AUDIT_ARCH_M68K: u32 = kernel_bindings::AUDIT_ARCH_M68K;
const AUDIT_ARCH_MICROBLAZE: u32 = kernel_bindings::AUDIT_ARCH_MICROBLAZE;
const AUDIT_ARCH_MIPS: u32 = kernel_bindings::AUDIT_ARCH_MIPS;
const AUDIT_ARCH_MIPSEL: u32 = kernel_bindings::AUDIT_ARCH_MIPSEL;
const AUDIT_ARCH_MIPS64: u32 = kernel_bindings::AUDIT_ARCH_MIPS64;
const AUDIT_ARCH_MIPS64N32: u32 = kernel_bindings::AUDIT_ARCH_MIPS64N32;
const AUDIT_ARCH_MIPSEL64: u32 = kernel_bindings::AUDIT_ARCH_MIPSEL64;
const AUDIT_ARCH_MIPSEL64N32: u32 = kernel_bindings::AUDIT_ARCH_MIPSEL64N32;
const AUDIT_ARCH_NDS32: u32 = kernel_bindings::AUDIT_ARCH_NDS32;
const AUDIT_ARCH_NDS32BE: u32 = kernel_bindings::AUDIT_ARCH_NDS32BE;
const AUDIT_ARCH_NIOS2: u32 = kernel_bindings::AUDIT_ARCH_NIOS2;
const AUDIT_ARCH_OPENRISC: u32 = kernel_bindings::AUDIT_ARCH_OPENRISC;
const AUDIT_ARCH_PARISC: u32 = kernel_bindings::AUDIT_ARCH_PARISC;
const AUDIT_ARCH_PARISC64: u32 = kernel_bindings::AUDIT_ARCH_PARISC64;
const AUDIT_ARCH_PPC: u32 = kernel_bindings::AUDIT_ARCH_PPC;
const AUDIT_ARCH_PPC64: u32 = kernel_bindings::AUDIT_ARCH_PPC64;
const AUDIT_ARCH_PPC64LE: u32 = kernel_bindings::AUDIT_ARCH_PPC64LE;
const AUDIT_ARCH_RISCV32: u32 = kernel_bindings::AUDIT_ARCH_RISCV32;
const AUDIT_ARCH_RISCV64: u32 = kernel_bindings::AUDIT_ARCH_RISCV64;
const AUDIT_ARCH_S390: u32 = kernel_bindings::AUDIT_ARCH_S390;
const AUDIT_ARCH_S390X: u32 = kernel_bindings::AUDIT_ARCH_S390X;
const AUDIT_ARCH_SH: u32 = kernel_bindings::AUDIT_ARCH_SH;
const AUDIT_ARCH_SHEL: u32 = kernel_bindings::AUDIT_ARCH_SHEL;
const AUDIT_ARCH_SH64: u32 = kernel_bindings::AUDIT_ARCH_SH64;
const AUDIT_ARCH_SHEL64: u32 = kernel_bindings::AUDIT_ARCH_SHEL64;
const AUDIT_ARCH_SPARC: u32 = kernel_bindings::AUDIT_ARCH_SPARC;
const AUDIT_ARCH_SPARC64: u32 = kernel_bindings::AUDIT_ARCH_SPARC64;
const AUDIT_ARCH_TILEGX: u32 = kernel_bindings::AUDIT_ARCH_TILEGX;
const AUDIT_ARCH_TILEGX32: u32 = kernel_bindings::AUDIT_ARCH_TILEGX32;
const AUDIT_ARCH_TILEPRO: u32 = kernel_bindings::AUDIT_ARCH_TILEPRO;
const AUDIT_ARCH_UNICORE: u32 = kernel_bindings::AUDIT_ARCH_UNICORE;
const AUDIT_ARCH_X86_64: u32 = kernel_bindings::AUDIT_ARCH_X86_64;
const AUDIT_ARCH_XTENSA: u32 = kernel_bindings::AUDIT_ARCH_XTENSA;
const AUDIT_ARCH_LOONGARCH32: u32 = kernel_bindings::AUDIT_ARCH_LOONGARCH32;
const AUDIT_ARCH_LOONGARCH64: u32 = kernel_bindings::AUDIT_ARCH_LOONGARCH64;

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
            Self::AARCH64 => write!(f, "AArch64"),
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::aarch64(AUDIT_ARCH_AARCH64, Some(AuditArch::AARCH64))]
    #[case::x86_64(AUDIT_ARCH_X86_64, Some(AuditArch::X86_64))]
    #[case::i386(AUDIT_ARCH_I386, Some(AuditArch::I386))]
    #[case::unknown(9999, None)]
    fn test_audit_arch(#[case] input: u32, #[case] expected: Option<AuditArch>) {
        let result = AuditArch::try_from(input).ok();
        assert_eq!(result, expected);
    }
}
