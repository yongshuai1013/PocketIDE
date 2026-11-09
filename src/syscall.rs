use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    TranslateGuestPath,
    VirtualizeIdentity,
    GuestMemory,
    GuestCpu,
    GuestProcess,
    BrokerDevice,
    BrokerFile,
    GuestMount,
    Forward,
    Deny,
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TranslateGuestPath => f.write_str("translate-guest-path"),
            Self::VirtualizeIdentity => f.write_str("virtualize-identity"),
            Self::GuestMemory => f.write_str("guest-memory"),
            Self::GuestCpu => f.write_str("guest-cpu-abi"),
            Self::GuestProcess => f.write_str("guest-process-state"),
            Self::BrokerDevice => f.write_str("broker-device"),
            Self::BrokerFile => f.write_str("broker-guest-fd"),
            Self::GuestMount => f.write_str("guest-mount-namespace"),
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
        | "rename" | "renameat" | "renameat2" | "access" | "faccessat" | "stat" | "stat64"
        | "lstat" | "fstatat64" | "newfstatat" | "readlink" | "readlinkat" | "chdir" | "getcwd"
        | "execve" | "execveat" | "chmod" | "fchmodat" | "chown" | "lchown" | "fchownat"
        | "truncate" | "utime" | "utimes" => Route::TranslateGuestPath,
        "getuid" | "getuid32" | "geteuid" | "geteuid32" | "getgid" | "getgid32" | "getegid"
        | "getegid32" | "getpid" | "getppid" | "gettid" => Route::VirtualizeIdentity,
        "brk" | "mmap2" | "munmap" | "mprotect" => Route::GuestMemory,
        "ARM_set_tls" | "set_tls" | "clock_gettime" | "nanosleep" | "gettimeofday" | "poll" => {
            Route::GuestCpu
        }
        "ioctl" | "select" | "mknod" | "mknodat" => Route::BrokerDevice,
        "mount" | "umount" | "umount2" => Route::GuestMount,
        "sigaction" | "umask" => Route::GuestProcess,
        "read" | "write" | "close" | "lseek" | "ftruncate" | "getdents64" | "dup" | "dup2"
        | "dup3" | "socket" | "socketpair" | "bind" | "listen" | "accept" | "getsockopt"
        | "recvfrom" => Route::BrokerFile,
        "fstat" | "fstat64" | "futex" | "sched_yield" | "pipe" | "pipe2" | "sendto" | "sendmsg"
        | "recvmsg" | "exit" | "exit_group" | "wait4" | "waitid" | "rt_sigprocmask"
        | "sigaltstack" | "madvise" | "getrandom" | "uname" => Route::Forward,
        "rt_sigaction" => Route::Deny,
        "mmap" | "ptrace" | "kexec_load" | "reboot" | "swapon" | "swapoff" | "pivot_root"
        | "setns" | "unshare" | "bpf" => Route::Deny,
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
    fn mount_calls_stay_in_the_guest_namespace_and_unknown_calls_are_not_forwarded() {
        assert_eq!(route_syscall("mount"), Route::GuestMount);
        assert_eq!(route_syscall("umount2"), Route::GuestMount);
        assert_eq!(route_syscall("pivot_root"), Route::Deny);
        assert_eq!(route_syscall("made_up_call"), Route::Deny);
    }

    #[test]
    fn android_32_bit_identity_calls_use_virtual_guest_identity() {
        assert_eq!(route_syscall("getuid32"), Route::VirtualizeIdentity);
        assert_eq!(route_syscall("geteuid32"), Route::VirtualizeIdentity);
        assert_eq!(route_syscall("getgid32"), Route::VirtualizeIdentity);
        assert_eq!(route_syscall("getegid32"), Route::VirtualizeIdentity);
    }

    #[test]
    fn device_interfaces_are_reserved_for_brokers() {
        assert_eq!(route_syscall("ioctl"), Route::BrokerDevice);
    }

    #[test]
    fn process_memory_calls_are_emulated_locally_not_forwarded() {
        assert_eq!(route_syscall("brk"), Route::GuestMemory);
        assert_eq!(route_syscall("mmap2"), Route::GuestMemory);
        assert_eq!(route_syscall("munmap"), Route::GuestMemory);
        assert_eq!(route_syscall("mprotect"), Route::GuestMemory);
        assert_eq!(route_syscall("mmap"), Route::Deny);
    }

    #[test]
    fn guest_file_descriptor_calls_use_the_file_broker() {
        assert_eq!(route_syscall("read"), Route::BrokerFile);
        assert_eq!(route_syscall("write"), Route::BrokerFile);
        assert_eq!(route_syscall("close"), Route::BrokerFile);
        assert_eq!(route_syscall("lseek"), Route::BrokerFile);
        assert_eq!(route_syscall("ftruncate"), Route::BrokerFile);
        assert_eq!(route_syscall("socket"), Route::BrokerFile);
        assert_eq!(route_syscall("socketpair"), Route::BrokerFile);
        assert_eq!(route_syscall("bind"), Route::BrokerFile);
        assert_eq!(route_syscall("listen"), Route::BrokerFile);
        assert_eq!(route_syscall("accept"), Route::BrokerFile);
        assert_eq!(route_syscall("getsockopt"), Route::BrokerFile);
        assert_eq!(route_syscall("recvfrom"), Route::BrokerFile);
        assert_eq!(route_syscall("stat64"), Route::TranslateGuestPath);
        assert_eq!(route_syscall("dup2"), Route::BrokerFile);
    }

    #[test]
    fn arm_thread_pointer_syscall_is_handled_by_guest_cpu_state() {
        assert_eq!(route_syscall("ARM_set_tls"), Route::GuestCpu);
        assert_eq!(route_syscall("set_tls"), Route::GuestCpu);
    }

    #[test]
    fn time_syscalls_are_served_by_the_guest_virtual_clock() {
        assert_eq!(route_syscall("clock_gettime"), Route::GuestCpu);
        assert_eq!(route_syscall("nanosleep"), Route::GuestCpu);
        assert_eq!(route_syscall("gettimeofday"), Route::GuestCpu);
        assert_eq!(route_syscall("poll"), Route::GuestCpu);
    }

    #[test]
    fn legacy_signal_registration_is_guest_state_but_rt_abi_is_not_claimed() {
        assert_eq!(route_syscall("sigaction"), Route::GuestProcess);
        assert_eq!(route_syscall("umask"), Route::GuestProcess);
        assert_eq!(route_syscall("rt_sigaction"), Route::Deny);
    }

    #[test]
    fn virtual_device_creation_stays_inside_the_broker() {
        assert_eq!(route_syscall("mknod"), Route::BrokerDevice);
        assert_eq!(route_syscall("mkdir"), Route::TranslateGuestPath);
        assert_eq!(route_syscall("unlink"), Route::TranslateGuestPath);
    }
}
