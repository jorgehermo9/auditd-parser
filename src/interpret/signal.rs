use std::fmt::{self, Display, Formatter};

// Constants are extracted from https://github.com/torvalds/linux/blob/4a95bc121ccdaee04c4d72f84dbfa6b880a514b6/include/uapi/asm-generic/signal.h#L11
// More information about signals can be found in https://man7.org/linux/man-pages/man7/signal.7.html
#[derive(Debug, PartialEq)]
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
        write!(f, "{:?}", self)
    }
}

impl TryFrom<u64> for Signal {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        // Constants are extracted from linux/include/uapi/asm-generic/signal.h
        // Some architectures may have different signal numbers
        // (as described by https://man7.org/linux/man-pages/man7/signal.7.html)
        // But for now we will support only the generic and POSIX-compatible ones
        let signal = match value {
            1 => Signal::SIGHUP,
            2 => Signal::SIGINT,
            3 => Signal::SIGQUIT,
            4 => Signal::SIGILL,
            5 => Signal::SIGTRAP,
            6 => Signal::SIGABRT,
            7 => Signal::SIGBUS,
            8 => Signal::SIGFPE,
            9 => Signal::SIGKILL,
            10 => Signal::SIGUSR1,
            11 => Signal::SIGSEGV,
            12 => Signal::SIGUSR2,
            13 => Signal::SIGPIPE,
            14 => Signal::SIGALRM,
            15 => Signal::SIGTERM,
            16 => Signal::SIGSTKFLT,
            17 => Signal::SIGCHLD,
            18 => Signal::SIGCONT,
            19 => Signal::SIGSTOP,
            20 => Signal::SIGTSTP,
            21 => Signal::SIGTTIN,
            22 => Signal::SIGTTOU,
            23 => Signal::SIGURG,
            24 => Signal::SIGXCPU,
            25 => Signal::SIGXFSZ,
            26 => Signal::SIGVTALRM,
            27 => Signal::SIGPROF,
            28 => Signal::SIGWINCH,
            29 => Signal::SIGPOLL,
            30 => Signal::SIGPWR,
            31 => Signal::SIGSYS,
            32 => Signal::SIGUNUSED,
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
    #[case::sigkill(4, Some(Signal::SIGILL))]
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
