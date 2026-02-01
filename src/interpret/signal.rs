#![allow(dead_code)]

use std::fmt::{self, Display, Formatter};

// Constants are extracted from https://github.com/torvalds/linux/blob/4a95bc121ccdaee04c4d72f84dbfa6b880a514b6/include/uapi/asm-generic/signal.h#L11
// More information about signals can be found in https://man7.org/linux/man-pages/man7/signal.7.html
const SIGHUP: u64 = 1;
const SIGINT: u64 = 2;
const SIGQUIT: u64 = 3;
const SIGILL: u64 = 4;
const SIGTRAP: u64 = 5;
const SIGABRT: u64 = 6;
const SIGBUS: u64 = 7;
const SIGFPE: u64 = 8;
const SIGKILL: u64 = 9;
const SIGUSR1: u64 = 10;
const SIGSEGV: u64 = 11;
const SIGUSR2: u64 = 12;
const SIGPIPE: u64 = 13;
const SIGALRM: u64 = 14;
const SIGTERM: u64 = 15;
const SIGSTKFLT: u64 = 16;
const SIGCHLD: u64 = 17;
const SIGCONT: u64 = 18;
const SIGSTOP: u64 = 19;
const SIGTSTP: u64 = 20;
const SIGTTIN: u64 = 21;
const SIGTTOU: u64 = 22;
const SIGURG: u64 = 23;
const SIGXCPU: u64 = 24;
const SIGXFSZ: u64 = 25;
const SIGVTALRM: u64 = 26;
const SIGPROF: u64 = 27;
const SIGWINCH: u64 = 28;
const SIGPOLL: u64 = 29;
const SIGPWR: u64 = 30;
const SIGSYS: u64 = 31;
const SIGUNUSED: u64 = 32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum Signal {
    SIGHUP,
    SIGINT,
    SIGQUIT,
    SIGILL,
    SIGTRAP,
    SIGABRT,
    #[allow(dead_code)]
    SIGIOT, // Synomym for SIGABRT, we will prefer SIGABRT over this one
    SIGBUS,
    SIGFPE,
    SIGKILL,
    SIGUSR1,
    SIGSEGV,
    SIGUSR2,
    SIGPIPE,
    SIGALRM,
    SIGTERM,
    SIGSTKFLT,
    SIGCHLD,
    SIGCONT,
    SIGSTOP,
    SIGTSTP,
    SIGTTIN,
    SIGTTOU,
    SIGURG,
    SIGXCPU,
    SIGXFSZ,
    SIGVTALRM,
    SIGPROF,
    SIGWINCH,
    SIGPOLL,
    #[allow(dead_code)]
    SIGIO, // Synomym for SIGPOLL, we will prefer SIGPOLL over this one
    SIGPWR,
    SIGSYS,
    SIGUNUSED,
}

impl Display for Signal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl TryFrom<u64> for Signal {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let signal = match value {
            SIGHUP => Signal::SIGHUP,
            SIGINT => Signal::SIGINT,
            SIGQUIT => Signal::SIGQUIT,
            SIGILL => Signal::SIGILL,
            SIGTRAP => Signal::SIGTRAP,
            SIGABRT => Signal::SIGABRT,
            SIGBUS => Signal::SIGBUS,
            SIGFPE => Signal::SIGFPE,
            SIGKILL => Signal::SIGKILL,
            SIGUSR1 => Signal::SIGUSR1,
            SIGSEGV => Signal::SIGSEGV,
            SIGUSR2 => Signal::SIGUSR2,
            SIGPIPE => Signal::SIGPIPE,
            SIGALRM => Signal::SIGALRM,
            SIGTERM => Signal::SIGTERM,
            SIGSTKFLT => Signal::SIGSTKFLT,
            SIGCHLD => Signal::SIGCHLD,
            SIGCONT => Signal::SIGCONT,
            SIGSTOP => Signal::SIGSTOP,
            SIGTSTP => Signal::SIGTSTP,
            SIGTTIN => Signal::SIGTTIN,
            SIGTTOU => Signal::SIGTTOU,
            SIGURG => Signal::SIGURG,
            SIGXCPU => Signal::SIGXCPU,
            SIGXFSZ => Signal::SIGXFSZ,
            SIGVTALRM => Signal::SIGVTALRM,
            SIGPROF => Signal::SIGPROF,
            SIGWINCH => Signal::SIGWINCH,
            SIGPOLL => Signal::SIGPOLL,
            SIGPWR => Signal::SIGPWR,
            SIGSYS => Signal::SIGSYS,
            SIGUNUSED => Signal::SIGUNUSED,
            _ => return Err(()),
        };
        Ok(signal)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::sighup(1, Some(Signal::SIGHUP))]
    #[case::sigint(2, Some(Signal::SIGINT))]
    #[case::sigquit(3, Some(Signal::SIGQUIT))]
    #[case::sigill(4, Some(Signal::SIGILL))]
    #[case::sigtrap(5, Some(Signal::SIGTRAP))]
    #[case::sigabrt(6, Some(Signal::SIGABRT))]
    #[case::sigbus(7, Some(Signal::SIGBUS))]
    #[case::sigfpe(8, Some(Signal::SIGFPE))]
    #[case::sigkill(9, Some(Signal::SIGKILL))]
    #[case::sigusr1(10, Some(Signal::SIGUSR1))]
    #[case::sigsegv(11, Some(Signal::SIGSEGV))]
    #[case::sigusr2(12, Some(Signal::SIGUSR2))]
    #[case::sigpipe(13, Some(Signal::SIGPIPE))]
    #[case::sigalrm(14, Some(Signal::SIGALRM))]
    #[case::sigterm(15, Some(Signal::SIGTERM))]
    #[case::sigstkflt(16, Some(Signal::SIGSTKFLT))]
    #[case::sigchld(17, Some(Signal::SIGCHLD))]
    #[case::sigcont(18, Some(Signal::SIGCONT))]
    #[case::sigstop(19, Some(Signal::SIGSTOP))]
    #[case::sigtstp(20, Some(Signal::SIGTSTP))]
    #[case::sigttin(21, Some(Signal::SIGTTIN))]
    #[case::sigttou(22, Some(Signal::SIGTTOU))]
    #[case::sigurg(23, Some(Signal::SIGURG))]
    #[case::sigxcpu(24, Some(Signal::SIGXCPU))]
    #[case::sigxfsz(25, Some(Signal::SIGXFSZ))]
    #[case::sigvtalrm(26, Some(Signal::SIGVTALRM))]
    #[case::sigprof(27, Some(Signal::SIGPROF))]
    #[case::sigwinch(28, Some(Signal::SIGWINCH))]
    #[case::sigpoll(29, Some(Signal::SIGPOLL))]
    #[case::sigpwr(30, Some(Signal::SIGPWR))]
    #[case::sigsys(31, Some(Signal::SIGSYS))]
    #[case::sigunused(32, Some(Signal::SIGUNUSED))]
    #[case::unknown(33, None)]
    fn test_resolve_signal(#[case] input: u64, #[case] expected: Option<Signal>) {
        let result = Signal::try_from(input).ok();
        assert_eq!(result, expected);
    }
}
