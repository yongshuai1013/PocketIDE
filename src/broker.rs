use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions as FsOpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::rc::Rc;

use crate::rootfs::{RootFs, RootFsError};

/// Maximum payload accepted by one broker read or write operation.
pub const MAX_TRANSFER_BYTES: usize = 1024 * 1024;
const FIRST_GUEST_FD: i32 = 3;
pub const SIMULATED_PROPERTY_NAME: &str = "debug.gingervm.simulated";
pub const SIMULATED_PROPERTY_VALUE: &str = "1";
const SIMULATED_PROPERTY_SOCKET: &[u8] = b"/dev/socket/property_service";
const PROPERTY_NAME_MAX: usize = 32;
const PROPERTY_VALUE_MAX: usize = 92;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

#[derive(Debug)]
enum GuestFile {
    Regular(File),
    Memory {
        path: String,
        cursor: usize,
        readable: bool,
        writable: bool,
    },
    Virtual {
        bytes: Vec<u8>,
        cursor: usize,
        readable: bool,
    },
    Directory {
        path: String,
        entries: Vec<DirectoryEntry>,
        cursor: usize,
    },
    Device {
        kind: VirtualDevice,
        readable: bool,
        writable: bool,
    },
    Socket(VirtualSocket),
}

#[derive(Debug)]
struct VirtualSocket {
    bound_address: Option<Vec<u8>>,
    listening: bool,
    incoming: Option<Rc<RefCell<VecDeque<u8>>>>,
    outgoing: Option<Rc<RefCell<VecDeque<u8>>>>,
    pending_connections: VecDeque<VirtualSocket>,
    peer_identity: Option<VirtualIdentity>,
}

#[derive(Debug)]
enum VirtualDevice {
    Null,
    Zero,
    Random(File),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VirtualMountKind {
    Tmpfs,
    DevPts,
    Proc,
    Sysfs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VirtualPathKind {
    OutsideMount,
    Missing,
    Directory,
    File,
    Device,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryEntry {
    name: String,
    inode: u64,
    file_type: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VirtualNode {
    Null,
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
    pub directory: bool,
}

impl OpenFlags {
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
        create: false,
        truncate: false,
        directory: false,
    };

    pub const WRITE_CREATE_TRUNCATE: Self = Self {
        read: false,
        write: true,
        create: true,
        truncate: true,
        directory: false,
    };
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestSyscall {
    Open {
        path: String,
        flags: OpenFlags,
    },
    OpenAt {
        dirfd: i32,
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
    Dup2 {
        old_fd: i32,
        new_fd: i32,
    },
    Stat {
        path: String,
    },
    Mkdir {
        path: String,
        mode: u32,
    },
    Mknod {
        path: String,
        mode: u32,
        device: u32,
    },
    Unlink {
        path: String,
    },
    Lseek {
        fd: i32,
        offset: i32,
        whence: i32,
    },
    Ftruncate {
        fd: i32,
        length: u64,
    },
    Socket {
        domain: i32,
        socket_type: i32,
        protocol: i32,
    },
    SocketPair {
        domain: i32,
        socket_type: i32,
        protocol: i32,
    },
    Bind {
        fd: i32,
        address: Vec<u8>,
    },
    Listen {
        fd: i32,
        backlog: i32,
    },
    Accept {
        fd: i32,
    },
    PeerCredentials {
        fd: i32,
    },
    Getdents64 {
        fd: i32,
        count: usize,
    },
    Mount {
        source: String,
        target: String,
        fs_type: String,
        flags: u32,
        data: Option<String>,
    },
    Umount {
        target: String,
        flags: u32,
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
            Self::OpenAt { .. } => "openat",
            Self::Read { .. } => "read",
            Self::Write { .. } => "write",
            Self::Close { .. } => "close",
            Self::Dup2 { .. } => "dup2",
            Self::Stat { .. } => "stat64",
            Self::Mkdir { .. } => "mkdir",
            Self::Mknod { .. } => "mknod",
            Self::Unlink { .. } => "unlink",
            Self::Lseek { .. } => "lseek",
            Self::Ftruncate { .. } => "ftruncate",
            Self::Socket { .. } => "socket",
            Self::SocketPair { .. } => "socketpair",
            Self::Bind { .. } => "bind",
            Self::Listen { .. } => "listen",
            Self::Accept { .. } => "accept",
            Self::PeerCredentials { .. } => "getsockopt(SO_PEERCRED)",
            Self::Getdents64 { .. } => "getdents64",
            Self::Mount { .. } => "mount",
            Self::Umount { .. } => "umount2",
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
    FileDescriptorPair(i32, i32),
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
    files: BTreeMap<i32, GuestFile>,
    standard_fds: [bool; 3],
    standard_null_fds: [bool; 3],
    virtual_nodes: BTreeMap<String, VirtualNode>,
    mounts: BTreeMap<String, VirtualMountKind>,
    tmpfs_directories: BTreeSet<String>,
    tmpfs_files: BTreeMap<String, Vec<u8>>,
    simulated_property_event_pending: bool,
}

impl SyscallBroker {
    pub fn new(rootfs: RootFs, identity: VirtualIdentity) -> Self {
        Self {
            rootfs,
            identity,
            files: BTreeMap::new(),
            standard_fds: [true; 3],
            standard_null_fds: [false; 3],
            virtual_nodes: BTreeMap::new(),
            mounts: BTreeMap::new(),
            tmpfs_directories: BTreeSet::new(),
            tmpfs_files: BTreeMap::new(),
            simulated_property_event_pending: false,
        }
    }

    /// Arrange one deterministic guest-local SETPROP connection for init's
    /// property service; this creates no host socket and represents no device.
    pub fn inject_simulated_property_event(&mut self) {
        self.simulated_property_event_pending = true;
    }

    pub fn rootfs(&self) -> &RootFs {
        &self.rootfs
    }

    pub fn identity(&self) -> VirtualIdentity {
        self.identity
    }

    pub fn dispatch(&mut self, syscall: &GuestSyscall) -> Result<BrokerValue, BrokerError> {
        match syscall {
            GuestSyscall::Open { path, flags } => self.open(path, *flags),
            GuestSyscall::OpenAt { dirfd, path, flags } => self.open_at(*dirfd, path, *flags),
            GuestSyscall::Read { fd, count } => self.read(*fd, *count),
            GuestSyscall::Write { fd, bytes } => self.write(*fd, bytes),
            GuestSyscall::Close { fd } => self.close(*fd),
            GuestSyscall::Dup2 { old_fd, new_fd } => self.dup2_null(*old_fd, *new_fd),
            GuestSyscall::Stat { path } => self.stat(path),
            GuestSyscall::Mkdir { path, mode } => self.mkdir(path, *mode),
            GuestSyscall::Mknod { path, mode, device } => self.mknod(path, *mode, *device),
            GuestSyscall::Unlink { path } => self.unlink(path),
            GuestSyscall::Lseek { fd, offset, whence } => self.lseek(*fd, *offset, *whence),
            GuestSyscall::Ftruncate { fd, length } => self.ftruncate(*fd, *length),
            GuestSyscall::Socket {
                domain,
                socket_type,
                protocol,
            } => self.socket(*domain, *socket_type, *protocol),
            GuestSyscall::SocketPair {
                domain,
                socket_type,
                protocol,
            } => self.socketpair(*domain, *socket_type, *protocol),
            GuestSyscall::Bind { fd, address } => self.bind(*fd, address),
            GuestSyscall::Listen { fd, backlog } => self.listen(*fd, *backlog),
            GuestSyscall::Accept { fd } => self.accept(*fd),
            GuestSyscall::PeerCredentials { fd } => self.peer_credentials(*fd),
            GuestSyscall::Getdents64 { fd, count } => self.getdents64(*fd, *count),
            GuestSyscall::Mount {
                source,
                target,
                fs_type,
                flags,
                data,
            } => self.mount(source, target, fs_type, *flags, data.as_deref()),
            GuestSyscall::Umount { target, flags } => self.umount(target, *flags),
            GuestSyscall::GetUid => Ok(BrokerValue::Identity(self.identity.uid)),
            GuestSyscall::GetGid => Ok(BrokerValue::Identity(self.identity.gid)),
            GuestSyscall::GetPid => Ok(BrokerValue::Identity(self.identity.pid)),
            GuestSyscall::Control { name } => Err(BrokerError::Denied(name.clone())),
        }
    }

    fn open(&mut self, guest_path: &str, flags: OpenFlags) -> Result<BrokerValue, BrokerError> {
        let path = normalize_guest_path(guest_path)?;
        self.open_guest_path(path, flags)
    }

    fn open_at(
        &mut self,
        dirfd: i32,
        guest_path: &str,
        flags: OpenFlags,
    ) -> Result<BrokerValue, BrokerError> {
        let path = if guest_path.starts_with('/') {
            normalize_guest_path(guest_path)?
        } else {
            let base = if dirfd == -100 {
                "/".to_owned()
            } else {
                match self.files.get(&dirfd) {
                    Some(GuestFile::Directory { path, .. }) => path.clone(),
                    Some(_) => return Err(BrokerError::Io(std::io::Error::from_raw_os_error(20))),
                    None => return Err(BrokerError::BadFileDescriptor(dirfd)),
                }
            };
            normalize_guest_path(&format!("{base}/{guest_path}"))?
        };
        self.open_guest_path(path, flags)
    }

    fn open_guest_path(
        &mut self,
        guest_path: String,
        flags: OpenFlags,
    ) -> Result<BrokerValue, BrokerError> {
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

        let virtual_node = self.virtual_nodes.get(&guest_path).copied();
        let device = match (guest_path.as_str(), virtual_node) {
            ("/dev/null", _) | (_, Some(VirtualNode::Null)) => Some(VirtualDevice::Null),
            ("/dev/zero", _) => Some(VirtualDevice::Zero),
            ("/dev/random" | "/dev/urandom", _) => {
                Some(VirtualDevice::Random(File::open("/dev/urandom")?))
            }
            _ => None,
        };
        let file = if let Some(kind) = device {
            if flags.directory {
                return Err(BrokerError::Io(std::io::Error::from_raw_os_error(20)));
            }
            GuestFile::Device {
                kind,
                readable: flags.read,
                writable: flags.write,
            }
        } else {
            match self.virtual_path_kind(&guest_path) {
                VirtualPathKind::Directory => {
                    if flags.write {
                        return Err(BrokerError::Io(std::io::Error::from_raw_os_error(21)));
                    }
                    GuestFile::Directory {
                        entries: self.directory_entries(&guest_path)?,
                        path: guest_path,
                        cursor: 0,
                    }
                }
                VirtualPathKind::File => {
                    if flags.directory {
                        return Err(BrokerError::Io(std::io::Error::from_raw_os_error(20)));
                    }
                    if self.mount_kind_for_path(&guest_path) == Some(VirtualMountKind::Tmpfs) {
                        if flags.truncate {
                            self.tmpfs_files.insert(guest_path.clone(), Vec::new());
                        }
                        GuestFile::Memory {
                            path: guest_path,
                            cursor: 0,
                            readable: flags.read,
                            writable: flags.write,
                        }
                    } else {
                        let bytes = self
                            .virtual_file_contents(&guest_path)
                            .ok_or_else(|| BrokerError::Io(std::io::Error::from_raw_os_error(2)))?;
                        if flags.write {
                            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(13)));
                        }
                        GuestFile::Virtual {
                            bytes,
                            cursor: 0,
                            readable: flags.read,
                        }
                    }
                }
                VirtualPathKind::Device => GuestFile::Device {
                    kind: VirtualDevice::Null,
                    readable: flags.read,
                    writable: flags.write,
                },
                VirtualPathKind::Missing => {
                    if self.mount_kind_for_path(&guest_path) == Some(VirtualMountKind::Tmpfs)
                        && flags.create
                    {
                        let parent = guest_parent(&guest_path)?;
                        if self.virtual_path_kind(&parent) != VirtualPathKind::Directory {
                            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(2)));
                        }
                        self.tmpfs_files.entry(guest_path.clone()).or_default();
                        if flags.truncate {
                            self.tmpfs_files.insert(guest_path.clone(), Vec::new());
                        }
                        GuestFile::Memory {
                            path: guest_path,
                            cursor: 0,
                            readable: flags.read,
                            writable: flags.write,
                        }
                    } else {
                        return Err(BrokerError::Io(std::io::Error::from_raw_os_error(2)));
                    }
                }
                VirtualPathKind::OutsideMount => {
                    let host_path: PathBuf = self.rootfs.map_absolute(&guest_path)?;
                    let metadata = fs::metadata(&host_path);
                    if metadata.as_ref().is_ok_and(|metadata| metadata.is_dir()) {
                        if flags.write {
                            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(21)));
                        }
                        GuestFile::Directory {
                            entries: self.directory_entries(&guest_path)?,
                            path: guest_path,
                            cursor: 0,
                        }
                    } else if metadata.is_ok() || flags.create {
                        if flags.directory {
                            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(20)));
                        }
                        let mut options = FsOpenOptions::new();
                        options
                            .read(flags.read)
                            .write(flags.write)
                            .create(flags.create)
                            .truncate(flags.truncate);
                        GuestFile::Regular(options.open(host_path)?)
                    } else {
                        return Err(BrokerError::Io(metadata.unwrap_err()));
                    }
                }
            }
        };
        let fd = self.allocate_fd()?;
        self.files.insert(fd, file);
        Ok(BrokerValue::FileDescriptor(fd))
    }

    fn mount(
        &mut self,
        source: &str,
        target: &str,
        fs_type: &str,
        flags: u32,
        data: Option<&str>,
    ) -> Result<BrokerValue, BrokerError> {
        let target = normalize_guest_path(target)?;
        if target == "/" || flags != 0 || data.is_some_and(|value| value.len() > 4096) {
            return Err(BrokerError::InvalidArgument(
                "unsupported guest mount options",
            ));
        }
        let kind = match (source, target.as_str(), fs_type) {
            ("tmpfs", _, "tmpfs") | ("none", _, "tmpfs") => VirtualMountKind::Tmpfs,
            ("proc", "/proc", "proc") => VirtualMountKind::Proc,
            ("sysfs", "/sys", "sysfs") => VirtualMountKind::Sysfs,
            ("devpts", "/dev/pts", "devpts") => VirtualMountKind::DevPts,
            _ => return Err(BrokerError::Io(std::io::Error::from_raw_os_error(19))),
        };
        if self.mounts.contains_key(&target) {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(16)));
        }
        if !self.guest_directory_exists(&target)? {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(2)));
        }
        self.mounts.insert(target.clone(), kind);
        if kind == VirtualMountKind::Tmpfs {
            self.virtual_nodes
                .retain(|path, _| !path_is_beneath(path, &target));
            self.tmpfs_files
                .retain(|path, _| !path_is_beneath(path, &target));
            self.tmpfs_directories
                .retain(|path| !path_is_beneath(path, &target));
            self.tmpfs_directories.insert(target);
        }
        Ok(BrokerValue::Unit)
    }

    fn umount(&mut self, target: &str, flags: u32) -> Result<BrokerValue, BrokerError> {
        let target = normalize_guest_path(target)?;
        if flags != 0 {
            return Err(BrokerError::InvalidArgument("unsupported umount flags"));
        }
        if self
            .mounts
            .keys()
            .any(|path| path != &target && path_is_beneath(path, &target))
        {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(16)));
        }
        let Some(kind) = self.mounts.remove(&target) else {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(22)));
        };
        if kind == VirtualMountKind::Tmpfs {
            self.tmpfs_files
                .retain(|path, _| !path_is_beneath(path, &target));
            self.tmpfs_directories
                .retain(|path| !path_is_beneath(path, &target));
        }
        Ok(BrokerValue::Unit)
    }

    fn getdents64(&mut self, fd: i32, count: usize) -> Result<BrokerValue, BrokerError> {
        check_transfer_size(count)?;
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        let GuestFile::Directory {
            entries, cursor, ..
        } = file
        else {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(20)));
        };
        let mut output = Vec::new();
        while *cursor < entries.len() {
            let entry = &entries[*cursor];
            let record_len = align_up(19 + entry.name.len() + 1, 8);
            if record_len > count.saturating_sub(output.len()) {
                if output.is_empty() {
                    return Err(BrokerError::Io(std::io::Error::from_raw_os_error(22)));
                }
                break;
            }
            let start = output.len();
            output.resize(start + record_len, 0);
            output[start..start + 8].copy_from_slice(&entry.inode.to_le_bytes());
            let next_offset = (*cursor + 1) as i64;
            output[start + 8..start + 16].copy_from_slice(&next_offset.to_le_bytes());
            output[start + 16..start + 18].copy_from_slice(&(record_len as u16).to_le_bytes());
            output[start + 18] = entry.file_type;
            output[start + 19..start + 19 + entry.name.len()]
                .copy_from_slice(entry.name.as_bytes());
            *cursor += 1;
        }
        Ok(BrokerValue::Bytes(output))
    }

    fn mount_kind_for_path(&self, path: &str) -> Option<VirtualMountKind> {
        self.mounts
            .iter()
            .filter(|(mountpoint, _)| path_is_beneath(path, mountpoint))
            .max_by_key(|(mountpoint, _)| mountpoint.len())
            .map(|(_, kind)| *kind)
    }

    fn virtual_path_kind(&self, path: &str) -> VirtualPathKind {
        let Some(kind) = self.mount_kind_for_path(path) else {
            return if self.virtual_nodes.contains_key(path) {
                VirtualPathKind::Device
            } else {
                VirtualPathKind::OutsideMount
            };
        };
        match kind {
            VirtualMountKind::Tmpfs => {
                if self.tmpfs_directories.contains(path) {
                    VirtualPathKind::Directory
                } else if self.tmpfs_files.contains_key(path) {
                    VirtualPathKind::File
                } else if self.virtual_nodes.contains_key(path)
                    || matches!(
                        path,
                        "/dev/null" | "/dev/zero" | "/dev/random" | "/dev/urandom"
                    )
                {
                    VirtualPathKind::Device
                } else {
                    VirtualPathKind::Missing
                }
            }
            VirtualMountKind::DevPts => {
                if self.mounts.contains_key(path) {
                    VirtualPathKind::Directory
                } else {
                    VirtualPathKind::Missing
                }
            }
            VirtualMountKind::Proc => match path {
                "/proc" | "/proc/sys" | "/proc/cpu" => VirtualPathKind::Directory,
                "/proc/cmdline" | "/proc/cpuinfo" => VirtualPathKind::File,
                _ => VirtualPathKind::Missing,
            },
            VirtualMountKind::Sysfs => match path {
                "/sys" | "/sys/class" | "/sys/block" | "/sys/devices" => VirtualPathKind::Directory,
                _ => VirtualPathKind::Missing,
            },
        }
    }

    fn virtual_file_contents(&self, path: &str) -> Option<Vec<u8>> {
        match path {
            "/proc/cmdline" | "/proc/cpuinfo" => Some(Vec::new()),
            _ => self.tmpfs_files.get(path).cloned(),
        }
    }

    fn guest_directory_exists(&self, path: &str) -> Result<bool, BrokerError> {
        match self.virtual_path_kind(path) {
            VirtualPathKind::Directory => Ok(true),
            VirtualPathKind::Missing | VirtualPathKind::File | VirtualPathKind::Device => Ok(false),
            VirtualPathKind::OutsideMount => {
                let host_path = self.rootfs.map_absolute(path)?;
                Ok(fs::metadata(host_path).is_ok_and(|metadata| metadata.is_dir()))
            }
        }
    }

    fn directory_entries(&self, path: &str) -> Result<Vec<DirectoryEntry>, BrokerError> {
        let mut names = BTreeMap::<String, u8>::new();
        match self.virtual_path_kind(path) {
            VirtualPathKind::Directory => {
                for directory in &self.tmpfs_directories {
                    if let Some(name) = direct_child_name(path, directory) {
                        names.insert(name.to_owned(), 4);
                    }
                }
                for file in self.tmpfs_files.keys() {
                    if let Some(name) = direct_child_name(path, file) {
                        names.insert(name.to_owned(), 8);
                    }
                }
                for node in self.virtual_nodes.keys() {
                    if let Some(name) = direct_child_name(path, node) {
                        names.insert(name.to_owned(), 2);
                    }
                }
                match path {
                    "/dev" => {
                        for name in ["null", "zero", "random", "urandom"] {
                            names.insert(name.to_owned(), 2);
                        }
                    }
                    "/proc" => {
                        for name in ["cmdline", "cpuinfo"] {
                            names.insert(name.to_owned(), 8);
                        }
                        names.insert("cpu".to_owned(), 4);
                        names.insert("sys".to_owned(), 4);
                    }
                    "/sys" => {
                        for name in ["class", "block", "devices"] {
                            names.insert(name.to_owned(), 4);
                        }
                    }
                    _ => {}
                }
                for mountpoint in self.mounts.keys() {
                    if let Some(name) = direct_child_name(path, mountpoint) {
                        names.insert(name.to_owned(), 4);
                    }
                }
            }
            VirtualPathKind::OutsideMount => {
                let host_path = self.rootfs.map_absolute(path)?;
                for entry in fs::read_dir(host_path)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let file_type = entry.file_type()?;
                    let kind = if file_type.is_dir() {
                        4
                    } else if file_type.is_file() {
                        8
                    } else if file_type.is_symlink() {
                        10
                    } else {
                        0
                    };
                    names.insert(name, kind);
                }
                for mountpoint in self.mounts.keys() {
                    if let Some(name) = direct_child_name(path, mountpoint) {
                        names.insert(name.to_owned(), 4);
                    }
                }
            }
            _ => return Err(BrokerError::Io(std::io::Error::from_raw_os_error(20))),
        }
        let mut entries = vec![
            DirectoryEntry {
                name: ".".to_owned(),
                inode: 1,
                file_type: 4,
            },
            DirectoryEntry {
                name: "..".to_owned(),
                inode: 2,
                file_type: 4,
            },
        ];
        for (index, (name, file_type)) in names.into_iter().enumerate() {
            entries.push(DirectoryEntry {
                name,
                inode: (index + 3) as u64,
                file_type,
            });
        }
        Ok(entries)
    }

    fn read(&mut self, fd: i32, count: usize) -> Result<BrokerValue, BrokerError> {
        check_transfer_size(count)?;
        if (0..=2).contains(&fd) {
            if !self.standard_fds[fd as usize] || fd != 0 {
                return Err(BrokerError::BadFileDescriptor(fd));
            }
            return Ok(BrokerValue::Bytes(Vec::new()));
        }
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        match file {
            GuestFile::Regular(file) => {
                let mut bytes = vec![0; count];
                let read = file.read(&mut bytes)?;
                bytes.truncate(read);
                Ok(BrokerValue::Bytes(bytes))
            }
            GuestFile::Memory {
                path,
                cursor,
                readable: true,
                ..
            } => {
                let data = self
                    .tmpfs_files
                    .get(path)
                    .ok_or_else(|| BrokerError::Io(std::io::Error::from_raw_os_error(2)))?;
                let end = cursor.saturating_add(count).min(data.len());
                let bytes = data[*cursor..end].to_vec();
                *cursor = end;
                Ok(BrokerValue::Bytes(bytes))
            }
            GuestFile::Virtual {
                bytes,
                cursor,
                readable: true,
            } => {
                let end = cursor.saturating_add(count).min(bytes.len());
                let result = bytes[*cursor..end].to_vec();
                *cursor = end;
                Ok(BrokerValue::Bytes(result))
            }
            GuestFile::Memory { .. } | GuestFile::Virtual { .. } => {
                Err(BrokerError::BadFileDescriptor(fd))
            }
            GuestFile::Directory { .. } => {
                Err(BrokerError::Io(std::io::Error::from_raw_os_error(21)))
            }
            GuestFile::Device {
                kind,
                readable: true,
                ..
            } => match kind {
                VirtualDevice::Null => Ok(BrokerValue::Bytes(Vec::new())),
                VirtualDevice::Zero => Ok(BrokerValue::Bytes(vec![0; count])),
                VirtualDevice::Random(source) => {
                    let mut bytes = vec![0; count];
                    let read = source.read(&mut bytes)?;
                    bytes.truncate(read);
                    Ok(BrokerValue::Bytes(bytes))
                }
            },
            GuestFile::Device {
                readable: false, ..
            } => Err(BrokerError::BadFileDescriptor(fd)),
            GuestFile::Socket(socket) => {
                let Some(incoming) = &socket.incoming else {
                    return Err(BrokerError::Io(std::io::Error::from_raw_os_error(107)));
                };
                let mut queue = incoming.borrow_mut();
                if queue.is_empty() && count != 0 {
                    return Err(BrokerError::Io(std::io::Error::from_raw_os_error(11)));
                }
                let count = count.min(queue.len());
                Ok(BrokerValue::Bytes(queue.drain(..count).collect()))
            }
        }
    }

    /// Read from a guest file descriptor at an explicit byte offset without
    /// changing the descriptor's sequential read position. Used by private
    /// guest mappings; the host file is never exposed as a guest pointer.
    pub(crate) fn read_file_at(
        &mut self,
        fd: i32,
        offset: u64,
        count: usize,
    ) -> Result<Vec<u8>, BrokerError> {
        check_transfer_size(count)?;
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        match file {
            GuestFile::Regular(file) => {
                let original_position = file.stream_position()?;
                let read_result = (|| {
                    file.seek(SeekFrom::Start(offset))?;
                    let mut bytes = vec![0; count];
                    let mut total = 0;
                    while total < count {
                        let read = file.read(&mut bytes[total..])?;
                        if read == 0 {
                            break;
                        }
                        total += read;
                    }
                    bytes.truncate(total);
                    Ok::<_, std::io::Error>(bytes)
                })();
                let restore_result = file.seek(SeekFrom::Start(original_position));
                restore_result?;
                read_result.map_err(BrokerError::Io)
            }
            GuestFile::Memory { path, .. } => {
                let data = self
                    .tmpfs_files
                    .get(path)
                    .ok_or_else(|| BrokerError::Io(std::io::Error::from_raw_os_error(2)))?;
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(count).min(data.len());
                Ok(data.get(start..end).unwrap_or_default().to_vec())
            }
            GuestFile::Virtual { bytes, .. } => {
                let start = usize::try_from(offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(count).min(bytes.len());
                Ok(bytes.get(start..end).unwrap_or_default().to_vec())
            }
            _ => Err(BrokerError::Io(std::io::Error::from_raw_os_error(19))),
        }
    }

    fn write(&mut self, fd: i32, bytes: &[u8]) -> Result<BrokerValue, BrokerError> {
        check_transfer_size(bytes.len())?;
        if (0..=2).contains(&fd) {
            if !self.standard_fds[fd as usize] || fd == 0 {
                return Err(BrokerError::BadFileDescriptor(fd));
            }
            if self.standard_null_fds[fd as usize] {
                return Ok(BrokerValue::Count(bytes.len()));
            }
            let mut stream: Box<dyn Write> = if fd == 1 {
                Box::new(std::io::stdout())
            } else {
                Box::new(std::io::stderr())
            };
            stream.write_all(bytes)?;
            stream.flush()?;
            return Ok(BrokerValue::Count(bytes.len()));
        }
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        match file {
            GuestFile::Regular(file) => {
                file.write_all(bytes)?;
                Ok(BrokerValue::Count(bytes.len()))
            }
            GuestFile::Memory {
                path,
                cursor,
                writable: true,
                ..
            } => {
                let data = self.tmpfs_files.entry(path.clone()).or_default();
                let end = cursor
                    .checked_add(bytes.len())
                    .ok_or(BrokerError::InvalidArgument("tmpfs file offset overflow"))?;
                if end > MAX_TRANSFER_BYTES {
                    return Err(BrokerError::TransferTooLarge {
                        requested: end,
                        maximum: MAX_TRANSFER_BYTES,
                    });
                }
                if *cursor > data.len() {
                    data.resize(*cursor, 0);
                }
                if end > data.len() {
                    data.resize(end, 0);
                }
                data[*cursor..end].copy_from_slice(bytes);
                *cursor = end;
                Ok(BrokerValue::Count(bytes.len()))
            }
            GuestFile::Memory { .. } | GuestFile::Virtual { .. } => {
                Err(BrokerError::BadFileDescriptor(fd))
            }
            GuestFile::Directory { .. } => {
                Err(BrokerError::Io(std::io::Error::from_raw_os_error(21)))
            }
            GuestFile::Device {
                kind: VirtualDevice::Null | VirtualDevice::Zero,
                writable: true,
                ..
            } => Ok(BrokerValue::Count(bytes.len())),
            GuestFile::Device {
                kind: VirtualDevice::Random(_),
                writable: true,
                ..
            } => Err(BrokerError::Denied(
                "writing guest random devices is not emulated".to_owned(),
            )),
            GuestFile::Device {
                writable: false, ..
            } => Err(BrokerError::BadFileDescriptor(fd)),
            GuestFile::Socket(socket) => {
                let Some(outgoing) = &socket.outgoing else {
                    return Err(BrokerError::Io(std::io::Error::from_raw_os_error(107)));
                };
                outgoing.borrow_mut().extend(bytes.iter().copied());
                Ok(BrokerValue::Count(bytes.len()))
            }
        }
    }

    fn close(&mut self, fd: i32) -> Result<BrokerValue, BrokerError> {
        if (0..=2).contains(&fd) {
            if !self.standard_fds[fd as usize] {
                return Err(BrokerError::BadFileDescriptor(fd));
            }
            self.standard_fds[fd as usize] = false;
            self.standard_null_fds[fd as usize] = false;
            return Ok(BrokerValue::Unit);
        }
        self.files
            .remove(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        Ok(BrokerValue::Unit)
    }

    /// Gingerbread init only needs dup2 to install its virtual /dev/null on
    /// stdin/stdout/stderr. Do not duplicate host-backed descriptors.
    fn dup2_null(&mut self, old_fd: i32, new_fd: i32) -> Result<BrokerValue, BrokerError> {
        let target = usize::try_from(new_fd)
            .ok()
            .filter(|index| *index < self.standard_fds.len())
            .ok_or_else(|| BrokerError::Denied("dup2 target outside guest stdio".to_owned()))?;
        if old_fd == new_fd {
            let is_open = if (0..=2).contains(&old_fd) {
                self.standard_fds[old_fd as usize]
            } else {
                self.files.contains_key(&old_fd)
            };
            return if is_open {
                Ok(BrokerValue::Count(new_fd as usize))
            } else {
                Err(BrokerError::BadFileDescriptor(old_fd))
            };
        }
        let source_is_null = if (0..=2).contains(&old_fd) {
            self.standard_fds[old_fd as usize] && self.standard_null_fds[old_fd as usize]
        } else {
            matches!(
                self.files.get(&old_fd),
                Some(GuestFile::Device {
                    kind: VirtualDevice::Null,
                    readable: true,
                    writable: true,
                })
            )
        };
        if !source_is_null {
            return Err(BrokerError::Denied(
                "dup2 only emulates virtual /dev/null onto stdio".to_owned(),
            ));
        }
        self.standard_fds[target] = true;
        self.standard_null_fds[target] = true;
        Ok(BrokerValue::Count(new_fd as usize))
    }

    fn mkdir(&mut self, guest_path: &str, mode: u32) -> Result<BrokerValue, BrokerError> {
        let guest_path = normalize_guest_path(guest_path)?;
        if self.mount_kind_for_path(&guest_path) == Some(VirtualMountKind::Tmpfs) {
            let parent = guest_parent(&guest_path)?;
            if self.virtual_path_kind(&parent) != VirtualPathKind::Directory {
                return Err(BrokerError::Io(std::io::Error::from_raw_os_error(2)));
            }
            if self.virtual_path_kind(&guest_path) != VirtualPathKind::Missing {
                return Err(BrokerError::Io(std::io::Error::from_raw_os_error(17)));
            }
            self.tmpfs_directories.insert(guest_path);
            return Ok(BrokerValue::Unit);
        }
        if self.virtual_path_kind(&guest_path) != VirtualPathKind::OutsideMount {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(30)));
        }
        let host_path = self.rootfs.map_absolute(&guest_path)?;
        fs::create_dir(&host_path)?;
        set_guest_mode(&host_path, mode & 0o7777)?;
        Ok(BrokerValue::Unit)
    }

    /// Emulate only the character devices init itself needs during startup;
    /// never create host device nodes or honor arbitrary guest major/minors.
    fn mknod(
        &mut self,
        guest_path: &str,
        mode: u32,
        device: u32,
    ) -> Result<BrokerValue, BrokerError> {
        const S_IFMT: u32 = 0o170000;
        const S_IFCHR: u32 = 0o020000;
        let kind = match (guest_path, mode & S_IFMT, device) {
            ("/dev/__null__", S_IFCHR, 0x103) | ("/dev/__kmsg__", S_IFCHR, 0x10b) => {
                VirtualNode::Null
            }
            _ => {
                return Err(BrokerError::Denied(
                    "mknod outside virtual init devices".to_owned(),
                ));
            }
        };
        let guest_path = normalize_guest_path(guest_path)?;
        let virtual_path = self.mount_kind_for_path(&guest_path) == Some(VirtualMountKind::Tmpfs);
        let host_path = if virtual_path {
            None
        } else {
            Some(self.rootfs.map_absolute(&guest_path)?)
        };
        if self.virtual_nodes.contains_key(&guest_path)
            || self.tmpfs_files.contains_key(&guest_path)
            || self.tmpfs_directories.contains(&guest_path)
            || host_path
                .as_ref()
                .is_some_and(|path| fs::symlink_metadata(path).is_ok())
        {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(17)));
        }
        self.virtual_nodes.insert(guest_path, kind);
        Ok(BrokerValue::Unit)
    }

    fn unlink(&mut self, guest_path: &str) -> Result<BrokerValue, BrokerError> {
        let guest_path = normalize_guest_path(guest_path)?;
        if self.virtual_nodes.remove(&guest_path).is_some() {
            return Ok(BrokerValue::Unit);
        }
        if self.tmpfs_files.remove(&guest_path).is_some() {
            return Ok(BrokerValue::Unit);
        }
        if self.mount_kind_for_path(&guest_path).is_some() {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(2)));
        }
        let host_path = self.rootfs.map_absolute(&guest_path)?;
        fs::remove_file(host_path)?;
        Ok(BrokerValue::Unit)
    }

    fn stat(&self, guest_path: &str) -> Result<BrokerValue, BrokerError> {
        const STAT64_SIZE: usize = 96;
        const S_IFREG: u32 = 0o100000;
        const S_IFDIR: u32 = 0o040000;

        let guest_path = normalize_guest_path(guest_path)?;
        match self.virtual_path_kind(&guest_path) {
            VirtualPathKind::Missing => {
                return Err(BrokerError::Io(std::io::Error::from_raw_os_error(2)));
            }
            VirtualPathKind::File => {
                return Ok(make_stat64(
                    self.identity,
                    S_IFREG | 0o444,
                    self.virtual_file_contents(&guest_path)
                        .map_or(0, |bytes| bytes.len()) as u64,
                ));
            }
            VirtualPathKind::Directory => {
                return Ok(make_stat64(self.identity, S_IFDIR | 0o755, 0));
            }
            VirtualPathKind::Device => {
                return Ok(make_stat64(self.identity, 0o020666, 0));
            }
            VirtualPathKind::OutsideMount => {}
        }
        let host_path = self.rootfs.map_absolute(&guest_path)?;
        let metadata = fs::metadata(host_path)?;
        let file_type = if metadata.is_file() {
            S_IFREG
        } else if metadata.is_dir() {
            S_IFDIR
        } else {
            metadata_file_type(&metadata)
        };
        let mode = file_type | if metadata.is_dir() { 0o755 } else { 0o644 };
        let mut bytes = vec![0; STAT64_SIZE];
        put_u32(&mut bytes, 16, mode);
        put_u32(&mut bytes, 20, 1);
        put_u32(&mut bytes, 24, self.identity.uid);
        put_u32(&mut bytes, 28, self.identity.gid);
        bytes[44..52].copy_from_slice(&(metadata.len() as i64).to_le_bytes());
        put_u32(&mut bytes, 52, 4096);
        bytes[56..64].copy_from_slice(&metadata.len().div_ceil(512).to_le_bytes());
        Ok(BrokerValue::Bytes(bytes))
    }

    fn lseek(&mut self, fd: i32, offset: i32, whence: i32) -> Result<BrokerValue, BrokerError> {
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        match file {
            GuestFile::Regular(file) => {
                let position = match whence {
                    0 if offset >= 0 => file.seek(SeekFrom::Start(offset as u64))?,
                    0 => return Err(BrokerError::InvalidArgument("negative SEEK_SET offset")),
                    1 => file.seek(SeekFrom::Current(offset as i64))?,
                    2 => file.seek(SeekFrom::End(offset as i64))?,
                    _ => return Err(BrokerError::InvalidArgument("unsupported lseek whence")),
                };
                let count = usize::try_from(position)
                    .map_err(|_| BrokerError::InvalidArgument("lseek result exceeds host range"))?;
                Ok(BrokerValue::Count(count))
            }
            GuestFile::Memory { path, cursor, .. } => {
                let length = self.tmpfs_files.get(path).map_or(0, Vec::len);
                *cursor = seek_memory_position(*cursor, length, offset, whence)?;
                Ok(BrokerValue::Count(*cursor))
            }
            GuestFile::Virtual { bytes, cursor, .. } => {
                *cursor = seek_memory_position(*cursor, bytes.len(), offset, whence)?;
                Ok(BrokerValue::Count(*cursor))
            }
            GuestFile::Directory {
                entries, cursor, ..
            } => {
                let position = seek_memory_position(*cursor, entries.len(), offset, whence)?;
                *cursor = position.min(entries.len());
                Ok(BrokerValue::Count(*cursor))
            }
            _ => Err(BrokerError::Io(std::io::Error::from_raw_os_error(29))),
        }
    }

    fn ftruncate(&mut self, fd: i32, length: u64) -> Result<BrokerValue, BrokerError> {
        let length_usize = usize::try_from(length)
            .map_err(|_| BrokerError::InvalidArgument("ftruncate length exceeds host range"))?;
        check_transfer_size(length_usize)?;
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        match file {
            GuestFile::Regular(file) => file.set_len(length)?,
            GuestFile::Memory {
                path,
                writable: true,
                ..
            } => self
                .tmpfs_files
                .entry(path.clone())
                .or_default()
                .resize(length_usize, 0),
            _ => return Err(BrokerError::Io(std::io::Error::from_raw_os_error(22))),
        }
        Ok(BrokerValue::Unit)
    }

    fn socket(
        &mut self,
        domain: i32,
        socket_type: i32,
        protocol: i32,
    ) -> Result<BrokerValue, BrokerError> {
        validate_local_stream_socket(domain, socket_type, protocol)?;
        let fd = self.allocate_fd()?;
        self.files.insert(
            fd,
            GuestFile::Socket(VirtualSocket {
                bound_address: None,
                listening: false,
                incoming: None,
                outgoing: None,
                pending_connections: VecDeque::new(),
                peer_identity: None,
            }),
        );
        Ok(BrokerValue::FileDescriptor(fd))
    }

    fn socketpair(
        &mut self,
        domain: i32,
        socket_type: i32,
        protocol: i32,
    ) -> Result<BrokerValue, BrokerError> {
        validate_local_stream_socket(domain, socket_type, protocol)?;
        let first_incoming = Rc::new(RefCell::new(VecDeque::new()));
        let second_incoming = Rc::new(RefCell::new(VecDeque::new()));
        let first_fd = self.allocate_fd()?;
        self.files.insert(
            first_fd,
            GuestFile::Socket(VirtualSocket {
                bound_address: None,
                listening: false,
                incoming: Some(first_incoming.clone()),
                outgoing: Some(second_incoming.clone()),
                pending_connections: VecDeque::new(),
                peer_identity: None,
            }),
        );
        let second_fd = match self.allocate_fd() {
            Ok(fd) => fd,
            Err(error) => {
                self.files.remove(&first_fd);
                return Err(error);
            }
        };
        self.files.insert(
            second_fd,
            GuestFile::Socket(VirtualSocket {
                bound_address: None,
                listening: false,
                incoming: Some(second_incoming),
                outgoing: Some(first_incoming),
                pending_connections: VecDeque::new(),
                peer_identity: None,
            }),
        );
        Ok(BrokerValue::FileDescriptorPair(first_fd, second_fd))
    }

    fn bind(&mut self, fd: i32, address: &[u8]) -> Result<BrokerValue, BrokerError> {
        if address.is_empty() || address.len() > 108 {
            return Err(BrokerError::InvalidArgument("invalid Unix socket address"));
        }
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        let GuestFile::Socket(socket) = file else {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(88)));
        };
        if socket.bound_address.is_some() {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(22)));
        }
        socket.bound_address = Some(address.to_vec());
        Ok(BrokerValue::Unit)
    }

    fn listen(&mut self, fd: i32, backlog: i32) -> Result<BrokerValue, BrokerError> {
        if backlog < 0 {
            return Err(BrokerError::InvalidArgument("negative listen backlog"));
        }
        let file = self
            .files
            .get_mut(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        let GuestFile::Socket(socket) = file else {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(88)));
        };
        if socket.bound_address.is_none() {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(22)));
        }
        socket.listening = true;
        if self.simulated_property_event_pending
            && socket.bound_address.as_deref() == Some(SIMULATED_PROPERTY_SOCKET)
        {
            let mut message = vec![0; 4 + PROPERTY_NAME_MAX + PROPERTY_VALUE_MAX];
            message[..4].copy_from_slice(&1u32.to_le_bytes()); // PROP_MSG_SETPROP
            let name = SIMULATED_PROPERTY_NAME.as_bytes();
            let value = SIMULATED_PROPERTY_VALUE.as_bytes();
            message[4..4 + name.len()].copy_from_slice(name);
            let value_start = 4 + PROPERTY_NAME_MAX;
            message[value_start..value_start + value.len()].copy_from_slice(value);
            socket.pending_connections.push_back(VirtualSocket {
                bound_address: None,
                listening: false,
                incoming: Some(Rc::new(RefCell::new(message.into_iter().collect()))),
                outgoing: None,
                pending_connections: VecDeque::new(),
                peer_identity: Some(VirtualIdentity {
                    uid: 2000,
                    gid: 2000,
                    pid: 4242,
                }),
            });
            self.simulated_property_event_pending = false;
        }
        Ok(BrokerValue::Unit)
    }

    fn accept(&mut self, fd: i32) -> Result<BrokerValue, BrokerError> {
        let accepted = {
            let file = self
                .files
                .get_mut(&fd)
                .ok_or(BrokerError::BadFileDescriptor(fd))?;
            let GuestFile::Socket(socket) = file else {
                return Err(BrokerError::Io(std::io::Error::from_raw_os_error(88)));
            };
            if !socket.listening {
                return Err(BrokerError::Io(std::io::Error::from_raw_os_error(22)));
            }
            socket.pending_connections.pop_front()
        };
        let Some(accepted) = accepted else {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(11)));
        };
        let accepted_fd = self.allocate_fd()?;
        self.files.insert(accepted_fd, GuestFile::Socket(accepted));
        Ok(BrokerValue::FileDescriptor(accepted_fd))
    }

    fn peer_credentials(&self, fd: i32) -> Result<BrokerValue, BrokerError> {
        let file = self
            .files
            .get(&fd)
            .ok_or(BrokerError::BadFileDescriptor(fd))?;
        let GuestFile::Socket(socket) = file else {
            return Err(BrokerError::Io(std::io::Error::from_raw_os_error(88)));
        };
        let identity = socket
            .peer_identity
            .ok_or_else(|| BrokerError::Io(std::io::Error::from_raw_os_error(92)))?;
        let mut credentials = Vec::with_capacity(12);
        credentials.extend_from_slice(&(identity.pid as i32).to_le_bytes());
        credentials.extend_from_slice(&(identity.uid as i32).to_le_bytes());
        credentials.extend_from_slice(&(identity.gid as i32).to_le_bytes());
        Ok(BrokerValue::Bytes(credentials))
    }

    pub(crate) fn poll_revents(&self, fd: i32, requested: u16) -> u16 {
        const POLLIN: u16 = 0x001;
        const POLLOUT: u16 = 0x004;
        const POLLNVAL: u16 = 0x020;
        if fd < 0 {
            return 0;
        }
        if (0..=2).contains(&fd) {
            let index = fd as usize;
            if !self.standard_fds[index] {
                return POLLNVAL;
            }
            return match fd {
                0 => requested & POLLIN,
                _ => requested & POLLOUT,
            };
        }
        match self.files.get(&fd) {
            None => POLLNVAL,
            Some(GuestFile::Regular(_) | GuestFile::Memory { .. }) => {
                requested & (POLLIN | POLLOUT)
            }
            Some(GuestFile::Virtual { readable, .. }) => {
                if *readable {
                    requested & POLLIN
                } else {
                    0
                }
            }
            Some(GuestFile::Directory { .. }) => requested & POLLIN,
            Some(GuestFile::Device {
                readable, writable, ..
            }) => {
                (if *readable { requested & POLLIN } else { 0 })
                    | (if *writable { requested & POLLOUT } else { 0 })
            }
            Some(GuestFile::Socket(socket)) => {
                let readable = socket
                    .incoming
                    .as_ref()
                    .is_some_and(|queue| !queue.borrow().is_empty())
                    || !socket.pending_connections.is_empty();
                (if readable { requested & POLLIN } else { 0 })
                    | (if socket.outgoing.is_some() {
                        requested & POLLOUT
                    } else {
                        0
                    })
            }
        }
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

fn normalize_guest_path(path: &str) -> Result<String, BrokerError> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(BrokerError::InvalidArgument(
            "guest path must be absolute and NUL-free",
        ));
    }
    let mut components = Vec::new();
    for component in std::path::Path::new(path).components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(name) => {
                components.push(name.to_string_lossy().into_owned());
            }
            std::path::Component::ParentDir | std::path::Component::Prefix(_) => {
                return Err(BrokerError::InvalidArgument(
                    "guest path traversal is not allowed",
                ));
            }
        }
    }
    if components.is_empty() {
        Ok("/".to_owned())
    } else {
        Ok(format!("/{}", components.join("/")))
    }
}

fn guest_parent(path: &str) -> Result<String, BrokerError> {
    let Some(index) = path.rfind('/') else {
        return Err(BrokerError::InvalidArgument("guest path has no parent"));
    };
    Ok(if index == 0 {
        "/".to_owned()
    } else {
        path[..index].to_owned()
    })
}

fn path_is_beneath(path: &str, mountpoint: &str) -> bool {
    path == mountpoint
        || path
            .strip_prefix(mountpoint)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn direct_child_name<'a>(parent: &str, candidate: &'a str) -> Option<&'a str> {
    let suffix = if parent == "/" {
        candidate.strip_prefix('/')?
    } else {
        candidate.strip_prefix(parent)?.strip_prefix('/')?
    };
    (!suffix.is_empty() && !suffix.contains('/')).then_some(suffix)
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

fn seek_memory_position(
    current: usize,
    length: usize,
    offset: i32,
    whence: i32,
) -> Result<usize, BrokerError> {
    let base = match whence {
        0 => 0_i128,
        1 => current as i128,
        2 => length as i128,
        _ => return Err(BrokerError::InvalidArgument("unsupported lseek whence")),
    };
    let position = base + i128::from(offset);
    usize::try_from(position)
        .map_err(|_| BrokerError::InvalidArgument("invalid or overflowing lseek offset"))
}

fn make_stat64(identity: VirtualIdentity, mode: u32, size: u64) -> BrokerValue {
    let mut bytes = vec![0; 96];
    put_u32(&mut bytes, 16, mode);
    put_u32(&mut bytes, 20, 1);
    put_u32(&mut bytes, 24, identity.uid);
    put_u32(&mut bytes, 28, identity.gid);
    bytes[44..52].copy_from_slice(&(size as i64).to_le_bytes());
    put_u32(&mut bytes, 52, 4096);
    bytes[56..64].copy_from_slice(&size.div_ceil(512).to_le_bytes());
    BrokerValue::Bytes(bytes)
}

#[cfg(unix)]
fn set_guest_mode(path: &std::path::Path, mode: u32) -> Result<(), BrokerError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_guest_mode(_path: &std::path::Path, _mode: u32) -> Result<(), BrokerError> {
    Ok(())
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

fn validate_local_stream_socket(
    domain: i32,
    socket_type: i32,
    protocol: i32,
) -> Result<(), BrokerError> {
    if domain != 1 {
        return Err(BrokerError::Io(std::io::Error::from_raw_os_error(97)));
    }
    if socket_type != 1 {
        return Err(BrokerError::Io(std::io::Error::from_raw_os_error(91)));
    }
    if protocol != 0 {
        return Err(BrokerError::Io(std::io::Error::from_raw_os_error(93)));
    }
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(unix)]
fn metadata_file_type(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::FileTypeExt;
    let kind = metadata.file_type();
    if kind.is_fifo() {
        0o010000
    } else if kind.is_socket() {
        0o140000
    } else if kind.is_block_device() {
        0o060000
    } else if kind.is_char_device() {
        0o020000
    } else {
        0
    }
}

#[cfg(not(unix))]
fn metadata_file_type(_metadata: &fs::Metadata) -> u32 {
    0
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
    fn ftruncate_resizes_only_a_guest_regular_file_inside_rootfs() {
        let (base, root) = test_root("ftruncate");
        let guest_path = root.root().join("tmp/property-area");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/tmp/property-area".to_owned(),
                    flags: OpenFlags::WRITE_CREATE_TRUNCATE,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Ftruncate {
                    fd: 3,
                    length: 32 * 1024,
                })
                .unwrap(),
            BrokerValue::Unit
        );
        assert_eq!(fs::metadata(&guest_path).unwrap().len(), 32 * 1024);
        assert_eq!(fs::read(&guest_path).unwrap(), vec![0; 32 * 1024]);
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Ftruncate {
                fd: 3,
                length: (MAX_TRANSFER_BYTES as u64) + 1,
            }),
            Err(BrokerError::TransferTooLarge { .. })
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn unix_property_socket_and_signal_socketpair_stay_guest_local() {
        let (base, root) = test_root("unix-sockets");
        let socket_path = root.root().join("dev/socket/property_service");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Socket {
                    domain: 1,
                    socket_type: 1,
                    protocol: 0,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Bind {
                    fd: 3,
                    address: b"/dev/socket/property_service".to_vec(),
                })
                .unwrap(),
            BrokerValue::Unit
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Listen { fd: 3, backlog: 8 })
                .unwrap(),
            BrokerValue::Unit
        );
        assert!(
            !socket_path.exists(),
            "virtual bind must not create a host socket"
        );

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::SocketPair {
                    domain: 1,
                    socket_type: 1,
                    protocol: 0,
                })
                .unwrap(),
            BrokerValue::FileDescriptorPair(4, 5)
        );
        assert_eq!(broker.poll_revents(5, 0x001), 0);
        assert_eq!(broker.poll_revents(4, 0x004), 0x004);
        assert_eq!(broker.poll_revents(99, 0x001), 0x020);
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Read { fd: 5, count: 32 }),
            Err(BrokerError::Io(error)) if error.raw_os_error() == Some(11)
        ));
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Write {
                    fd: 4,
                    bytes: b"signal".to_vec(),
                })
                .unwrap(),
            BrokerValue::Count(6)
        );
        assert_eq!(broker.poll_revents(5, 0x001), 0x001);
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 5, count: 32 })
                .unwrap(),
            BrokerValue::Bytes(b"signal".to_vec())
        );
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Socket {
                domain: 2,
                socket_type: 1,
                protocol: 0,
            }),
            Err(BrokerError::Io(error)) if error.raw_os_error() == Some(97)
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn simulated_property_event_is_one_guest_local_setprop_connection() {
        let (base, root) = test_root("simulated-property-event");
        let socket_path = root.root().join("dev/socket/property_service");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        broker.inject_simulated_property_event();
        broker
            .dispatch(&GuestSyscall::Socket {
                domain: 1,
                socket_type: 1,
                protocol: 0,
            })
            .unwrap();
        broker
            .dispatch(&GuestSyscall::Bind {
                fd: 3,
                address: SIMULATED_PROPERTY_SOCKET.to_vec(),
            })
            .unwrap();
        broker
            .dispatch(&GuestSyscall::Listen { fd: 3, backlog: 8 })
            .unwrap();
        assert_eq!(broker.poll_revents(3, 0x001), 0x001);
        assert!(
            !socket_path.exists(),
            "simulation must not create a host socket"
        );
        assert_eq!(
            broker.dispatch(&GuestSyscall::Accept { fd: 3 }).unwrap(),
            BrokerValue::FileDescriptor(4)
        );
        let BrokerValue::Bytes(credentials) = broker
            .dispatch(&GuestSyscall::PeerCredentials { fd: 4 })
            .unwrap()
        else {
            panic!("peer credentials must be bytes");
        };
        assert_eq!(credentials.len(), 12);
        assert_eq!(
            i32::from_le_bytes(credentials[0..4].try_into().unwrap()),
            4242
        );
        assert_eq!(
            i32::from_le_bytes(credentials[4..8].try_into().unwrap()),
            2000
        );
        assert_eq!(
            i32::from_le_bytes(credentials[8..12].try_into().unwrap()),
            2000
        );
        let BrokerValue::Bytes(message) = broker
            .dispatch(&GuestSyscall::Read { fd: 4, count: 128 })
            .unwrap()
        else {
            panic!("property message must be bytes");
        };
        assert_eq!(message.len(), 128);
        assert_eq!(u32::from_le_bytes(message[0..4].try_into().unwrap()), 1);
        assert_eq!(
            &message[4..4 + SIMULATED_PROPERTY_NAME.len()],
            SIMULATED_PROPERTY_NAME.as_bytes()
        );
        assert_eq!(
            &message[36..36 + SIMULATED_PROPERTY_VALUE.len()],
            SIMULATED_PROPERTY_VALUE.as_bytes()
        );
        assert_eq!(broker.poll_revents(3, 0x001), 0);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn standard_input_is_eof_and_closed_standard_descriptors_stay_closed() {
        let (base, root) = test_root("stdio");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 0, count: 8 })
                .unwrap(),
            BrokerValue::Bytes(Vec::new())
        );
        assert_eq!(
            broker.dispatch(&GuestSyscall::Close { fd: 2 }).unwrap(),
            BrokerValue::Unit
        );
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Write {
                fd: 2,
                bytes: b"closed".to_vec()
            }),
            Err(BrokerError::BadFileDescriptor(2))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn android_character_devices_are_virtual_and_confined_to_guest_fds() {
        let (base, root) = test_root("devices");
        let guest_dev = root.root().join("dev");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        let read_write = OpenFlags {
            read: true,
            write: true,
            create: false,
            truncate: false,
            directory: false,
        };

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/dev/null".to_owned(),
                    flags: read_write,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 3, count: 8 })
                .unwrap(),
            BrokerValue::Bytes(Vec::new())
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Write {
                    fd: 3,
                    bytes: b"discarded".to_vec(),
                })
                .unwrap(),
            BrokerValue::Count(9)
        );
        broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/dev/zero".to_owned(),
                    flags: read_write,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 3, count: 16 })
                .unwrap(),
            BrokerValue::Bytes(vec![0; 16])
        );
        broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();

        for path in ["/dev/random", "/dev/urandom"] {
            assert_eq!(
                broker
                    .dispatch(&GuestSyscall::Open {
                        path: path.to_owned(),
                        flags: OpenFlags::READ_ONLY,
                    })
                    .unwrap(),
                BrokerValue::FileDescriptor(3)
            );
            assert!(matches!(
                broker.dispatch(&GuestSyscall::Read { fd: 3, count: 32 }),
                Ok(BrokerValue::Bytes(bytes)) if bytes.len() == 32
            ));
            assert!(matches!(
                broker.dispatch(&GuestSyscall::Write {
                    fd: 3,
                    bytes: b"not entropy input".to_vec(),
                }),
                Err(BrokerError::BadFileDescriptor(3))
            ));
            broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();
        }

        for name in ["null", "zero", "random", "urandom"] {
            assert!(
                !guest_dev.join(name).exists(),
                "virtual device /dev/{name} must not create a host node"
            );
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn gingerbread_init_null_device_setup_is_virtual_and_guest_local() {
        let (base, root) = test_root("init-null-device");
        let device_path = root.root().join("dev/__null__");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Mknod {
                    path: "/dev/__null__".to_owned(),
                    mode: 0o020000 | 0o600,
                    device: 0x103,
                })
                .unwrap(),
            BrokerValue::Unit
        );
        assert!(
            !device_path.exists(),
            "mknod must not touch the host device table"
        );

        let read_write = OpenFlags {
            read: true,
            write: true,
            create: false,
            truncate: false,
            directory: false,
        };
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/dev/__null__".to_owned(),
                    flags: read_write,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        broker
            .dispatch(&GuestSyscall::Unlink {
                path: "/dev/__null__".to_owned(),
            })
            .unwrap();
        for fd in 0..=2 {
            assert_eq!(
                broker
                    .dispatch(&GuestSyscall::Dup2 {
                        old_fd: 3,
                        new_fd: fd,
                    })
                    .unwrap(),
                BrokerValue::Count(fd as usize)
            );
        }
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 0, count: 4 })
                .unwrap(),
            BrokerValue::Bytes(Vec::new())
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Write {
                    fd: 1,
                    bytes: b"discarded".to_vec(),
                })
                .unwrap(),
            BrokerValue::Count(9)
        );
        broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Mknod {
                path: "/dev/host-device".to_owned(),
                mode: 0o020000 | 0o666,
                device: 0x103,
            }),
            Err(BrokerError::Denied(_))
        ));
        assert!(!base.join("root/dev/host-device").exists());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn guest_mkdir_stays_under_root_and_applies_guest_mode() {
        let (base, root) = test_root("mkdir");
        let directory = root.root().join("tmp/guest-dir");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Mkdir {
                    path: "/tmp/guest-dir".to_owned(),
                    mode: 0o700,
                })
                .unwrap(),
            BrokerValue::Unit
        );
        assert!(directory.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn positioned_file_reads_do_not_move_the_guest_descriptor_cursor() {
        let (base, root) = test_root("pread");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        let path = "/tmp/mapped-file".to_owned();
        broker
            .dispatch(&GuestSyscall::Open {
                path: path.clone(),
                flags: OpenFlags::WRITE_CREATE_TRUNCATE,
            })
            .unwrap();
        broker
            .dispatch(&GuestSyscall::Write {
                fd: 3,
                bytes: b"abcdefghijklmnop".to_vec(),
            })
            .unwrap();
        broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();
        broker
            .dispatch(&GuestSyscall::Open {
                path,
                flags: OpenFlags::READ_ONLY,
            })
            .unwrap();

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 3, count: 4 })
                .unwrap(),
            BrokerValue::Bytes(b"abcd".to_vec())
        );
        assert_eq!(broker.read_file_at(3, 8, 4).unwrap(), b"ijkl");
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 3, count: 4 })
                .unwrap(),
            BrokerValue::Bytes(b"efgh".to_vec())
        );
        assert!(broker.read_file_at(3, 99, 4).unwrap().is_empty());
        assert!(matches!(
            broker.read_file_at(99, 0, 1),
            Err(BrokerError::BadFileDescriptor(99))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn stat64_is_guest_root_relative_and_lseek_updates_guest_fd_position() {
        let (base, root) = test_root("stat-lseek");
        let fixture = root.root().join("system/lib/libprobe.so");
        fs::create_dir_all(fixture.parent().unwrap()).unwrap();
        fs::write(&fixture, b"ELF probe data").unwrap();
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());

        let stat = broker
            .dispatch(&GuestSyscall::Stat {
                path: "/system/lib/libprobe.so".to_owned(),
            })
            .unwrap();
        let BrokerValue::Bytes(stat) = stat else {
            panic!("stat64 did not return a kernel-layout byte buffer");
        };
        assert_eq!(stat.len(), 96);
        assert_eq!(
            u32::from_le_bytes(stat[16..20].try_into().unwrap()) & 0o170000,
            0o100000
        );
        assert_eq!(i64::from_le_bytes(stat[44..52].try_into().unwrap()), 14);

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/system/lib/libprobe.so".to_owned(),
                    flags: OpenFlags::READ_ONLY,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Lseek {
                    fd: 3,
                    offset: -4,
                    whence: 2,
                })
                .unwrap(),
            BrokerValue::Count(10)
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 3, count: 4 })
                .unwrap(),
            BrokerValue::Bytes(b"data".to_vec())
        );
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
                name: "pivot_root".to_owned()
            }),
            Err(BrokerError::Denied(name)) if name == "pivot_root"
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

#[cfg(test)]
mod namespace_tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> (PathBuf, RootFs) {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!(
            "gingervm-namespace-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&base);
        let root = RootFs::open(base.join("root")).unwrap();
        root.initialize_layout().unwrap();
        (base, root)
    }

    fn decode_dirent64_names(bytes: &[u8]) -> Vec<String> {
        let mut names = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            assert!(bytes.len() - offset >= 19, "truncated dirent64 header");
            let record_len = u16::from_le_bytes([bytes[offset + 16], bytes[offset + 17]]) as usize;
            assert!(record_len >= 20 && offset + record_len <= bytes.len());
            let name_bytes = &bytes[offset + 19..offset + record_len];
            let name_end = name_bytes.iter().position(|byte| *byte == 0).unwrap();
            names.push(String::from_utf8(name_bytes[..name_end].to_vec()).unwrap());
            offset += record_len;
        }
        names
    }

    #[test]
    fn proc_and_dev_mounts_are_guest_only_and_tmpfs_is_not_host_backed() {
        let (base, root) = test_root("mounts");
        fs::write(root.root().join("proc/cmdline"), b"host-backed decoy\n").unwrap();
        fs::write(root.root().join("dev/hidden"), b"must be hidden").unwrap();
        let host_proc = root.root().join("proc/cmdline");
        let host_dev_file = root.root().join("dev/guest-only");
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());

        for (source, target, fs_type) in [("proc", "/proc", "proc"), ("tmpfs", "/dev", "tmpfs")] {
            assert_eq!(
                broker
                    .dispatch(&GuestSyscall::Mount {
                        source: source.to_owned(),
                        target: target.to_owned(),
                        fs_type: fs_type.to_owned(),
                        flags: 0,
                        data: None,
                    })
                    .unwrap(),
                BrokerValue::Unit
            );
        }

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/proc/cmdline".to_owned(),
                    flags: OpenFlags::READ_ONLY,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 3, count: 64 })
                .unwrap(),
            BrokerValue::Bytes(Vec::new())
        );
        broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();
        assert_eq!(fs::read(&host_proc).unwrap(), b"host-backed decoy\n");

        assert!(matches!(
            broker.dispatch(&GuestSyscall::Open {
                path: "/dev/hidden".to_owned(),
                flags: OpenFlags::READ_ONLY,
            }),
            Err(BrokerError::Io(error)) if error.raw_os_error() == Some(2)
        ));
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/dev/guest-only".to_owned(),
                    flags: OpenFlags::WRITE_CREATE_TRUNCATE,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        broker
            .dispatch(&GuestSyscall::Write {
                fd: 3,
                bytes: b"only in the guest tmpfs".to_vec(),
            })
            .unwrap();
        broker.dispatch(&GuestSyscall::Close { fd: 3 }).unwrap();
        assert!(!host_dev_file.exists(), "tmpfs must not create a host file");
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Open {
                    path: "/dev/guest-only".to_owned(),
                    flags: OpenFlags::READ_ONLY,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(3)
        );
        assert_eq!(
            broker
                .dispatch(&GuestSyscall::Read { fd: 3, count: 64 })
                .unwrap(),
            BrokerValue::Bytes(b"only in the guest tmpfs".to_vec())
        );
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Mount {
                source: "mtd@system".to_owned(),
                target: "/system".to_owned(),
                fs_type: "yaffs2".to_owned(),
                flags: 0,
                data: None,
            }),
            Err(BrokerError::Io(error)) if error.raw_os_error() == Some(19)
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn sysfs_getdents64_and_openat_expose_only_empty_virtual_device_tree() {
        let (base, root) = test_root("getdents64");
        fs::write(root.root().join("sys/host-only"), b"hidden").unwrap();
        let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
        broker
            .dispatch(&GuestSyscall::Mount {
                source: "sysfs".to_owned(),
                target: "/sys".to_owned(),
                fs_type: "sysfs".to_owned(),
                flags: 0,
                data: None,
            })
            .unwrap();
        let directory_flags = OpenFlags {
            read: true,
            write: false,
            create: false,
            truncate: false,
            directory: true,
        };
        broker
            .dispatch(&GuestSyscall::Open {
                path: "/sys".to_owned(),
                flags: directory_flags,
            })
            .unwrap();
        let BrokerValue::Bytes(root_entries) = broker
            .dispatch(&GuestSyscall::Getdents64 { fd: 3, count: 512 })
            .unwrap()
        else {
            panic!("getdents64 did not return a byte buffer");
        };
        assert_eq!(
            decode_dirent64_names(&root_entries),
            [".", "..", "block", "class", "devices"]
        );

        assert_eq!(
            broker
                .dispatch(&GuestSyscall::OpenAt {
                    dirfd: 3,
                    path: "class".to_owned(),
                    flags: directory_flags,
                })
                .unwrap(),
            BrokerValue::FileDescriptor(4)
        );
        let BrokerValue::Bytes(class_entries) = broker
            .dispatch(&GuestSyscall::Getdents64 { fd: 4, count: 512 })
            .unwrap()
        else {
            panic!("getdents64 did not return class directory entries");
        };
        assert_eq!(decode_dirent64_names(&class_entries), [".", ".."]);
        assert!(matches!(
            broker.dispatch(&GuestSyscall::OpenAt {
                dirfd: 4,
                path: "uevent".to_owned(),
                flags: OpenFlags::READ_ONLY,
            }),
            Err(BrokerError::Io(error)) if error.raw_os_error() == Some(2)
        ));
        assert!(matches!(
            broker.dispatch(&GuestSyscall::Open {
                path: "/sys/host-only".to_owned(),
                flags: OpenFlags::READ_ONLY,
            }),
            Err(BrokerError::Io(error)) if error.raw_os_error() == Some(2)
        ));
        let _ = fs::remove_dir_all(base);
    }
}
