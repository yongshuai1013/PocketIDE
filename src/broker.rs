use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs::{File, OpenOptions as FsOpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::rootfs::{RootFs, RootFsError};

/// Maximum payload accepted by one broker read or write operation.
pub const MAX_TRANSFER_BYTES: usize = 1024 * 1024;
const FIRST_GUEST_FD: i32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl Default for VirtualIdentity {
    fn default() -> Self {
        Self {
            uid: 1000,
            gid: 1000,
            pid: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags {
    pub read: bool,
    pub write: bool,
    pub create: bool,
    pub truncate: bool,
}

impl OpenFlags {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        create: false,
        truncate: false,
    };

    pub const WRITE_CREATE_TRUNCATE: Self = Self {
        read: false,
        write: true,
        create: true,
        truncate: true,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestSyscall {
    Open {
        path: String,
        flags: OpenFlags,
    },
    Read {
        fd: i32,
        count: usize,
    },
    Write {
        fd: i32,
        bytes: Vec<u8>,
    },
    Close {
        fd: i32,
    },
    GetUid,
    GetGid,
    GetPid,
    /// Host-control and unimplemented calls are deliberately denied.
    Control {
        name: String,
    },
}

impl GuestSyscall {
    pub fn name(&self) -> &str {
        match self {
            Self::Open { .. } => "open",
            Self::Read { .. } => "read",
            Self::Write { .. } => "write",
            Self::Close { .. } => "close",
            Self::GetUid => "getuid",
            Self::GetGid => "getgid",
            Self::GetPid => "getpid",
            Self::Control { name } => name,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerValue {
    FileDescriptor(i32),
    Bytes(Vec<u8>),
    Count(usize),
    Identity(u32),
    Unit,
}

#[derive(Debug)]
pub enum BrokerError {
    InvalidArgument(&'static str),
    BadFileDescriptor(i32),
    TransferTooLarge { requested: usize, maximum: usize },
    Denied(String),
    RootFs(RootFsError),
    Io(std::io::Error),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) => write!(f, "invalid syscall argument: {message}"),
            Self::BadFileDescriptor(fd) => write!(f, "bad guest file descriptor: {fd}"),
            Self::TransferTooLarge { requested, maximum } => {
                write!(
                    f,
                    "I/O size {requested} exceeds broker limit {maximum} bytes"
                )
            }
            Self::Denied(name) => write!(f, "syscall denied by broker policy: {name}"),
            Self::RootFs(error) => write!(f, "guest path rejected: {error}"),
            Self::Io(error) => write!(f, "broker I/O error: {error}"),
        }
    }
}

impl Error for BrokerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RootFs(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RootFsError> for BrokerError {
    fn from(value: RootFsError) -> Self {
        Self::RootFs(value)
    }
}

impl From<std::io::Error> for BrokerError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// One guest instance's deliberately small syscall broker.
///
/// This executes broker requests inside the host process. It is a testable
/// compatibility component, not a kernel syscall interceptor or a security
/// boundary. RootFs currently performs path checks by canonicalizing paths;
/// descriptor-relative operations are still required to close symlink races.
pub struct SyscallBroker {
    rootfs: RootFs,
    identity: VirtualIdentity,
    files: BTreeMap<i32, File>,
}

impl SyscallBroker {
    pub fn new(rootfs: RootFs, identity: VirtualIdentity) -> Self {
        Self {
            rootfs,
            identity,
            files: BTreeMap::new(),
        }
    }

    pub fn rootfs(&self) -> &RootFs {
        &self.rootfs
    }

    pub fn dispatch(&mut self, syscall: &GuestSyscall) -> Result<BrokerValue, BrokerError> {
        match syscall {
            GuestSyscall::Open { path, flags } => self.open(path, *flags),
            GuestSyscall::Read { fd, count } => self.read(*fd, *count),
            GuestSyscall::Write { fd, bytes } => self.write(*fd, bytes),
            GuestSyscall::Close { fd } => {
                self.files
                    .remove(fd)
                    .ok_or(BrokerError::BadFileDescriptor(*fd))?;
                Ok(BrokerValue::Unit)
            }
            GuestSyscall::GetUid => Ok(BrokerValue::Identity(self.identity.uid)),
            GuestSyscall::GetGid => Ok(BrokerValue::Identity(self.identity.gid)),
            GuestSyscall::GetPid => Ok(BrokerValue::Identity(self.identity.pid)),
            GuestSyscall::Control { name } => Err(BrokerError::Denied(name.clone())),
        }
    }

    fn open(&mut self, guest_path: &str, flags: OpenFlags) -> Result<BrokerValue, BrokerError> {
        if !flags.read && !flags.write {
            return Err(BrokerError::InvalidArgument(
                "open needs read or write access",
            ));
        }
        if (flags.create || flags.truncate) && !flags.write {
            return Err(BrokerError::InvalidArgument(
                "create/truncate requires write access in this broker subset",
            ));
        }

        let host_path: PathBuf = self.rootfs.map_absolute(guest_path)?;
        let mut options = FsOpenOptions::new();
        options
            .read(flags.read)
            .write(flags.write)
            .create(flags.create)
            .truncate(flags.truncate);
        let file = options.open(host_path)?;
        let fd = self.allocate_fd()?;
        self.files.insert(fd, file);
        Ok(BrokerValue::FileDescriptor(fd))
    }

    fn read(&mut self, fd: i32, count: usize) -> Result<BrokerValue, BrokerError> {
        check_transfer_size(count)?;
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        let mut bytes = vec![0; count];
        let read = file.read(&mut bytes)?;
        bytes.truncate(read);
        Ok(BrokerValue::Bytes(bytes))
    }

    fn write(&mut self, fd: i32, bytes: &[u8]) -> Result<BrokerValue, BrokerError> {
        check_transfer_size(bytes.len())?;
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        file.write_all(bytes)?;
        Ok(BrokerValue::Count(bytes.len()))
    }

    fn allocate_fd(&self) -> Result<i32, BrokerError> {
        let mut candidate = FIRST_GUEST_FD;
        while self.files.contains_key(&candidate) {
            candidate = candidate
                .checked_add(1)
                .ok_or(BrokerError::InvalidArgument("guest fd table exhausted"))?;
        }
        Ok(candidate)
    }
}

fn check_transfer_size(size: usize) -> Result<(), BrokerError> {
    if size > MAX_TRANSFER_BYTES {
        return Err(BrokerError::TransferTooLarge {
            requested: size,
            maximum: MAX_TRANSFER_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> (PathBuf, RootFs) {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "gingervm-broker-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let root = RootFs::open(base.join("root")).unwrap();
        root.initialize_layout().unwrap();
        (base, root)
    }

    #[test]
    fn file_descriptors_are_guest_local_and_reused_after_close() {
        let (base, root) = test_root("fds");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        let path = "/tmp/fd-test".to_owned();
        let fd = broker
            .dispatch(&GuestSyscall::Open {
                path: path.clone(),
                flags: OpenFlags::WRITE_CREATE_TRUNCATE,
            })
            .unwrap();
        assert_eq!(fd, BrokerValue::FileDescriptor(3));
        broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();
        let next_fd = broker
            .dispatch(&GuestSyscall::Open {
                path,
                flags: OpenFlags::READ_ONLY,
            })
            .unwrap();
        assert_eq!(next_fd, BrokerValue::FileDescriptor(3));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn virtual_identity_is_returned_without_exposing_host_identity() {
        let (base, root) = test_root("identity");
        let identity = VirtualIdentity {
            uid: 10042,
            gid: 10042,
            pid: 7,
        };
        let mut broker = SyscallBroker::new(root, identity);
        assert_eq!(
            broker.dispatch(&GuestSyscall::GetUid).unwrap(),
            BrokerValue::Identity(10042)
        );
        assert_eq!(
            broker.dispatch(&GuestSyscall::GetPid).unwrap(),
            BrokerValue::Identity(7)
        );
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn host_control_calls_are_denied_and_oversized_reads_are_bounded() {
        let (base, root) = test_root("deny");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Control {
                name: "mount".to_owned()
            }),
            Err(BrokerError::Denied(name)) if name == "mount"
        ));
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Read {
                fd: 3,
                count: MAX_TRANSFER_BYTES + 1
            }),
            Err(BrokerError::TransferTooLarge { .. })
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn open_rejects_paths_that_resolve_outside_guest_root() {
        use std::os::unix::fs::symlink;
        let (base, root) = test_root("escape");
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, root.root().join("escape")).unwrap();
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Open {
                path: "/escape/secret".to_owned(),
                flags: OpenFlags::READ_ONLY
            }),
            Err(BrokerError::RootFs(_))
        ));
        let _ = fs::remove_dir_all(base);
    }
}
