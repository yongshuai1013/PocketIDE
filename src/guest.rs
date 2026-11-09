use std::error::Error;
use std::fmt;

use crate::broker::{BrokerError, BrokerValue, GuestSyscall, SyscallBroker};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProgram {
    pub name: String,
    pub syscalls: Vec<GuestSyscall>,
}

impl GuestProgram {
    pub fn new(name: impl Into<String>, syscalls: Vec<GuestSyscall>) -> Self {
        Self {
            name: name.into(),
            syscalls,
        }
    }

    /// Execute the program's explicit syscall sequence against one guest broker.
    ///
    /// This is a host-side execution harness for testing the guest/broker ABI;
    /// it does not decode ARM instructions or launch an Android process.
    pub fn run(&self, broker: &mut SyscallBroker) -> Result<GuestExecutionReport, GuestRunError> {
        let mut events = Vec::with_capacity(self.syscalls.len());
        for (step, syscall) in self.syscalls.iter().enumerate() {
            let result = broker.dispatch(syscall).map_err(|source| GuestRunError {
                program: self.name.clone(),
                step,
                syscall: Box::new(syscall.clone()),
                source,
            })?;
            events.push(GuestEvent {
                step,
                syscall: syscall.clone(),
                result,
            });
        }
        Ok(GuestExecutionReport {
            program: self.name.clone(),
            events,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestEvent {
    /// Zero-based position in the program's syscall list.
    pub step: usize,
    pub syscall: GuestSyscall,
    pub result: BrokerValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestExecutionReport {
    pub program: String,
    pub events: Vec<GuestEvent>,
}

#[derive(Debug)]
pub struct GuestRunError {
    pub program: String,
    pub step: usize,
    pub syscall: Box<GuestSyscall>,
    pub source: BrokerError,
}

impl fmt::Display for GuestRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "guest program '{}' failed at syscall step {} ({}): {}",
            self.program,
            self.step,
            self.syscall.name(),
            self.source
        )
    }
}

impl Error for GuestRunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::{OpenFlags, VirtualIdentity};
    use crate::rootfs::RootFs;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_root() -> (PathBuf, RootFs) {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("gingervm-guest-loop-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = RootFs::open(base.join("root")).unwrap();
        root.initialize_layout().unwrap();
        (base, root)
    }

    #[test]
    fn guest_program_writes_reads_and_gets_virtual_identity_through_broker() {
        let (base, root) = test_root();
        let mut broker = SyscallBroker::new(
            root,
            VirtualIdentity {
                uid: 10042,
                gid: 10042,
                pid: 17,
            },
        );
        let payload = b"gingervm guest-to-broker round trip\n".to_vec();
        let program = GuestProgram::new(
            "file-round-trip",
            vec![
                GuestSyscall::Open {
                    path: "/tmp/probe.txt".to_owned(),
                    flags: OpenFlags::WRITE_CREATE_TRUNCATE,
                },
                GuestSyscall::Write {
                    fd: 3,
                    bytes: payload.clone(),
                },
                GuestSyscall::Close { fd: 3 },
                GuestSyscall::Open {
                    path: "/tmp/probe.txt".to_owned(),
                    flags: OpenFlags::READ_ONLY,
                },
                GuestSyscall::Read { fd: 3, count: 128 },
                GuestSyscall::Close { fd: 3 },
                GuestSyscall::GetUid,
                GuestSyscall::GetGid,
                GuestSyscall::GetPid,
            ],
        );

        let report = program.run(&mut broker).unwrap();
        assert_eq!(report.events.len(), 9);
        assert_eq!(report.events[1].result, BrokerValue::Count(payload.len()));
        assert_eq!(report.events[4].result, BrokerValue::Bytes(payload));
        assert_eq!(report.events[6].result, BrokerValue::Identity(10042));
        assert_eq!(report.events[7].result, BrokerValue::Identity(10042));
        assert_eq!(report.events[8].result, BrokerValue::Identity(17));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn guest_loop_reports_denied_syscall_and_stops_at_its_step() {
        let (base, root) = test_root();
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        let program = GuestProgram::new(
            "denied-pivot-root",
            vec![
                GuestSyscall::GetUid,
                GuestSyscall::Control {
                    name: "pivot_root".to_owned(),
                },
                GuestSyscall::GetGid,
            ],
        );

        let error = program.run(&mut broker).unwrap_err();
        assert_eq!(error.step, 1);
        assert_eq!(error.syscall.name(), "pivot_root");
        assert!(error.to_string().contains("denied by broker policy"));
        let _ = fs::remove_dir_all(base);
    }
}
