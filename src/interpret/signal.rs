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
        match self {
            Signal::SIGHUP => write!(f, "SIGHUP"),
            Signal::SIGINT => write!(f, "SIGINT"),
            Signal::SIGQUIT => write!(f, "SIGQUIT"),
            Signal::SIGILL => write!(f, "SIGILL"),
            Signal::SIGTRAP => write!(f, "SIGTRAP"),
            Signal::SIGABRT => write!(f, "SIGABRT"),
            Signal::SIGIOT => write!(f, "SIGIOT"),
            Signal::SIGBUS => write!(f, "SIGBUS"),
            Signal::SIGFPE => write!(f, "SIGFPE"),
            Signal::SIGKILL => write!(f, "SIGKILL"),
            Signal::SIGUSR1 => write!(f, "SIGUSR1"),
            Signal::SIGSEGV => write!(f, "SIGSEGV"),
            Signal::SIGUSR2 => write!(f, "SIGUSR2"),
            Signal::SIGPIPE => write!(f, "SIGPIPE"),
            Signal::SIGALRM => write!(f, "SIGALRM"),
            Signal::SIGTERM => write!(f, "SIGTERM"),
            Signal::SIGSTKFLT => write!(f, "SIGSTKFLT"),
            Signal::SIGCHLD => write!(f, "SIGCHLD"),
            Signal::SIGCONT => write!(f, "SIGCONT"),
            Signal::SIGSTOP => write!(f, "SIGSTOP"),
            Signal::SIGTSTP => write!(f, "SIGTSTP"),
            Signal::SIGTTIN => write!(f, "SIGTTIN"),
            Signal::SIGTTOU => write!(f, "SIGTTOU"),
            Signal::SIGURG => write!(f, "SIGURG"),
            Signal::SIGXCPU => write!(f, "SIGXCPU"),
            Signal::SIGXFSZ => write!(f, "SIGXFSZ"),
            Signal::SIGVTALRM => write!(f, "SIGVTALRM"),
            Signal::SIGPROF => write!(f, "SIGPROF"),
            Signal::SIGWINCH => write!(f, "SIGWINCH"),
            Signal::SIGPOLL => write!(f, "SIGPOLL"),
            Signal::SIGIO => write!(f, "SIGIO"),
            Signal::SIGPWR => write!(f, "SIGPWR"),
            Signal::SIGSYS => write!(f, "SIGSYS"),
            Signal::SIGUNUSED => write!(f, "SIGUNUSED"),
        }
    }
}

pub fn resolve_signal(signal: u64) -> Option<Signal> {
    // Constants from linux/include/uapi/asm-generic/signal.h
    // Some architectures may have different signal numbers
    // (as described by https://man7.org/linux/man-pages/man7/signal.7.html)
    // But for now we will support only the generic and POSIX-compatible ones
    let signal = match signal {
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
        _ => return None,
    };

    Some(signal)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::sighup(1, Signal::SIGHUP)]
    #[case::sigint(2, Signal::SIGINT)]
    #[case::sigquit(3, Signal::SIGQUIT)]
    #[case::sigkill(4, Signal::SIGILL)]
    #[case::sigtrap(5, Signal::SIGTRAP)]
    #[case::sigabrt(6, Signal::SIGABRT)]
    #[case::sigbus(7, Signal::SIGBUS)]
    #[case::sigfpe(8, Signal::SIGFPE)]
    #[case::sigkill(9, Signal::SIGKILL)]
    #[case::sigusr1(10, Signal::SIGUSR1)]
    #[case::sigsegv(11, Signal::SIGSEGV)]
    #[case::sigusr2(12, Signal::SIGUSR2)]
    #[case::sigpipe(13, Signal::SIGPIPE)]
    #[case::sigalrm(14, Signal::SIGALRM)]
    #[case::sigterm(15, Signal::SIGTERM)]
    #[case::sigstkflt(16, Signal::SIGSTKFLT)]
    #[case::sigchld(17, Signal::SIGCHLD)]
    #[case::sigcont(18, Signal::SIGCONT)]
    #[case::sigstop(19, Signal::SIGSTOP)]
    #[case::sigtstp(20, Signal::SIGTSTP)]
    #[case::sigttin(21, Signal::SIGTTIN)]
    #[case::sigttou(22, Signal::SIGTTOU)]
    #[case::sigurg(23, Signal::SIGURG)]
    #[case::sigxcpu(24, Signal::SIGXCPU)]
    #[case::sigxfsz(25, Signal::SIGXFSZ)]
    #[case::sigvtalrm(26, Signal::SIGVTALRM)]
    #[case::sigprof(27, Signal::SIGPROF)]
    #[case::sigwinch(28, Signal::SIGWINCH)]
    #[case::sigpoll(29, Signal::SIGPOLL)]
    #[case::sigpwr(30, Signal::SIGPWR)]
    #[case::sigsys(31, Signal::SIGSYS)]
    #[case::sigunused(32, Signal::SIGUNUSED)]
    fn test_resolve_signal(#[case] input: u64, #[case] expected: Signal) {
        let result = resolve_signal(input).unwrap();
        assert_eq!(result, expected);
    }
}
