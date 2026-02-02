#![allow(dead_code)]

use std::fmt::{self, Display, Formatter};

use crate::kernel_bindings;

// Signal constants are now imported from kernel headers via bindgen
// See kernel_bindings module for details
const SIGHUP: u64 = kernel_bindings::SIGHUP as u64;
const SIGINT: u64 = kernel_bindings::SIGINT as u64;
const SIGQUIT: u64 = kernel_bindings::SIGQUIT as u64;
const SIGILL: u64 = kernel_bindings::SIGILL as u64;
const SIGTRAP: u64 = kernel_bindings::SIGTRAP as u64;
const SIGABRT: u64 = kernel_bindings::SIGABRT as u64;
const SIGBUS: u64 = kernel_bindings::SIGBUS as u64;
const SIGFPE: u64 = kernel_bindings::SIGFPE as u64;
const SIGKILL: u64 = kernel_bindings::SIGKILL as u64;
const SIGUSR1: u64 = kernel_bindings::SIGUSR1 as u64;
const SIGSEGV: u64 = kernel_bindings::SIGSEGV as u64;
const SIGUSR2: u64 = kernel_bindings::SIGUSR2 as u64;
const SIGPIPE: u64 = kernel_bindings::SIGPIPE as u64;
const SIGALRM: u64 = kernel_bindings::SIGALRM as u64;
const SIGTERM: u64 = kernel_bindings::SIGTERM as u64;
const SIGSTKFLT: u64 = kernel_bindings::SIGSTKFLT as u64;
const SIGCHLD: u64 = kernel_bindings::SIGCHLD as u64;
const SIGCONT: u64 = kernel_bindings::SIGCONT as u64;
const SIGSTOP: u64 = kernel_bindings::SIGSTOP as u64;
const SIGTSTP: u64 = kernel_bindings::SIGTSTP as u64;
const SIGTTIN: u64 = kernel_bindings::SIGTTIN as u64;
const SIGTTOU: u64 = kernel_bindings::SIGTTOU as u64;
const SIGURG: u64 = kernel_bindings::SIGURG as u64;
const SIGXCPU: u64 = kernel_bindings::SIGXCPU as u64;
const SIGXFSZ: u64 = kernel_bindings::SIGXFSZ as u64;
const SIGVTALRM: u64 = kernel_bindings::SIGVTALRM as u64;
const SIGPROF: u64 = kernel_bindings::SIGPROF as u64;
const SIGWINCH: u64 = kernel_bindings::SIGWINCH as u64;
const SIGPOLL: u64 = kernel_bindings::SIGPOLL as u64;
const SIGPWR: u64 = kernel_bindings::SIGPWR as u64;
const SIGSYS: u64 = kernel_bindings::SIGSYS as u64;
// Note: SIGUNUSED is typically the same as SIGSYS on Linux
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
