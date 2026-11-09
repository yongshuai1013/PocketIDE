use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    TranslateGuestPath,
    VirtualizeIdentity,
    BrokerDevice,
    BrokerFile,
    Forward,
    Deny,
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TranslateGuestPath => f.write_str("translate-guest-path"),
            Self::VirtualizeIdentity => f.write_str("virtualize-identity"),
            Self::BrokerDevice => f.write_str("broker-device"),
            Self::BrokerFile => f.write_str("broker-guest-fd"),
            Self::Forward => f.write_str("forward"),
            Self::Deny => f.write_str("deny-unknown-or-host-control"),
        }
    }
}

/// Return the planned route for a named Linux syscall. Unknown calls default
/// to deny until an explicit compatibility decision is made.
pub fn route_syscall(name: &str) -> Route {
    match name {
        "open" | "openat" | "creat" | "mkdir" | "mkdirat" | "rmdir" | "unlink" | "unlinkat"
        | "rename" | "renameat" | "renameat2" | "access" | "faccessat" | "stat" | "lstat"
        | "fstatat64" | "newfstatat" | "readlink" | "readlinkat" | "chdir" | "getcwd"
        | "execve" | "execveat" | "chmod" | "fchmodat" | "chown" | "lchown" | "fchownat"
        | "truncate" | "utime" | "utimes" => Route::TranslateGuestPath,
        "getuid" | "geteuid" | "getgid" | "getegid" | "getpid" | "getppid" | "gettid" => {
            Route::VirtualizeIdentity
        }
        "ioctl" | "mmap" | "mmap2" | "poll" | "select" => Route::BrokerDevice,
        "read" | "write" | "close" => Route::BrokerFile,
        "dup" | "dup2" | "dup3" | "fstat" | "fstat64" | "lseek" | "futex" | "clock_gettime"
        | "nanosleep" | "sched_yield" | "gettimeofday" | "pipe" | "pipe2" | "socket"
        | "socketpair" | "sendto" | "recvfrom" | "sendmsg" | "recvmsg" | "exit" | "exit_group"
        | "wait4" | "waitid" | "rt_sigaction" | "rt_sigprocmask" | "sigaltstack" | "brk"
        | "munmap" | "mprotect" | "madvise" | "getrandom" | "uname" => Route::Forward,
        "mount" | "umount" | "umount2" | "ptrace" | "kexec_load" | "reboot" | "swapon"
        | "swapoff" | "pivot_root" | "setns" | "unshare" | "bpf" => Route::Deny,
        _ => Route::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_calls_are_guest_relative() {
        assert_eq!(route_syscall("openat"), Route::TranslateGuestPath);
        assert_eq!(route_syscall("rename"), Route::TranslateGuestPath);
    }

    #[test]
    fn host_escape_and_unknown_calls_are_not_forwarded() {
        assert_eq!(route_syscall("mount"), Route::Deny);
        assert_eq!(route_syscall("made_up_call"), Route::Deny);
    }

    #[test]
    fn device_interfaces_are_reserved_for_brokers() {
        assert_eq!(route_syscall("ioctl"), Route::BrokerDevice);
    }

    #[test]
    fn guest_file_descriptor_calls_use_the_file_broker() {
        assert_eq!(route_syscall("read"), Route::BrokerFile);
        assert_eq!(route_syscall("write"), Route::BrokerFile);
        assert_eq!(route_syscall("close"), Route::BrokerFile);
    }
}
