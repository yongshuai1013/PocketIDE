use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};

/// Filesystem namespace for one guest instance.
///
/// This is a path-policy prototype, not a security boundary. A hostile,
/// concurrent guest requires descriptor-relative operations (and platform
/// mediation) to close TOCTOU races; that layer is intentionally a later
/// milestone.
#[derive(Debug, Clone)]
pub struct RootFs {
    root: PathBuf,
}

#[derive(Debug)]
pub enum RootFsError {
    InvalidGuestPath(String),
    EscapesRoot(String),
    Io(std::io::Error),
}

impl fmt::Display for RootFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGuestPath(p) => {
                write!(f, "guest path must be absolute and normalized: {p}")
            }
            Self::EscapesRoot(p) => write!(f, "guest path resolves outside its root: {p}"),
            Self::Io(e) => write!(f, "rootfs I/O error: {e}"),
        }
    }
}

impl Error for RootFsError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RootFsError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl RootFs {
    /// Open an existing root directory or create it, then retain its canonical path.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RootFsError> {
        let root = root.as_ref();
        fs::create_dir_all(root)?;
        let root = root.canonicalize()?;
        if !root.is_dir() {
            return Err(RootFsError::InvalidGuestPath(root.display().to_string()));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Build the initial Android-like directory layout for a fresh guest.
    pub fn initialize_layout(&self) -> Result<(), RootFsError> {
        for guest_dir in [
            "/cache", "/data", "/dev", "/etc", "/mnt", "/proc", "/sdcard", "/sys", "/system",
            "/tmp", "/vendor",
        ] {
            let host_dir = self.map_absolute(guest_dir)?;
            fs::create_dir_all(host_dir)?;
        }
        Ok(())
    }

    /// Resolve an absolute guest path into this root, rejecting `..` and
    /// existing symlinks whose canonical destination escapes the root.
    pub fn map_absolute(&self, guest_path: &str) -> Result<PathBuf, RootFsError> {
        let path = Path::new(guest_path);
        if !path.is_absolute() {
            return Err(RootFsError::InvalidGuestPath(guest_path.to_owned()));
        }

        let mut candidate = self.root.clone();
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(name) => candidate.push(name),
                Component::ParentDir | Component::Prefix(_) => {
                    return Err(RootFsError::InvalidGuestPath(guest_path.to_owned()));
                }
            }
        }

        let resolved = self.resolve_existing_ancestor(&candidate, guest_path)?;
        if !resolved.starts_with(&self.root) {
            return Err(RootFsError::EscapesRoot(guest_path.to_owned()));
        }
        Ok(resolved)
    }

    fn resolve_existing_ancestor(
        &self,
        candidate: &Path,
        guest_path: &str,
    ) -> Result<PathBuf, RootFsError> {
        let mut ancestor = candidate;
        let mut suffix = Vec::new();

        loop {
            // `is_symlink` also catches a dangling link, which must not be
            // treated as a safe, not-yet-created path.
            if ancestor.exists() || fs::symlink_metadata(ancestor).is_ok() {
                let canonical = ancestor
                    .canonicalize()
                    .map_err(|_| RootFsError::EscapesRoot(guest_path.to_owned()))?;
                let mut resolved = canonical;
                for part in suffix.iter().rev() {
                    resolved.push(part);
                }
                return Ok(resolved);
            }
            let name = ancestor
                .file_name()
                .ok_or_else(|| RootFsError::InvalidGuestPath(guest_path.to_owned()))?;
            suffix.push(name.to_os_string());
            ancestor = ancestor
                .parent()
                .ok_or_else(|| RootFsError::InvalidGuestPath(guest_path.to_owned()))?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temporary_dir(label: &str) -> PathBuf {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("gingervm-{label}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn maps_guest_absolute_paths_beneath_root() {
        let base = temporary_dir("map");
        let root = RootFs::open(base.join("root")).unwrap();
        assert_eq!(
            root.map_absolute("/tmp/out.txt").unwrap(),
            root.root().join("tmp/out.txt")
        );
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn rejects_relative_and_parent_traversal_paths() {
        let base = temporary_dir("traversal");
        let root = RootFs::open(base.join("root")).unwrap();
        assert!(matches!(
            root.map_absolute("tmp/out.txt"),
            Err(RootFsError::InvalidGuestPath(_))
        ));
        assert!(matches!(
            root.map_absolute("/../../etc/passwd"),
            Err(RootFsError::InvalidGuestPath(_))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        let base = temporary_dir("symlink");
        let outside = base.join("outside");
        let root_path = base.join("root");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&root_path).unwrap();
        symlink(&outside, root_path.join("escape")).unwrap();
        let root = RootFs::open(&root_path).unwrap();
        assert!(matches!(
            root.map_absolute("/escape/secret"),
            Err(RootFsError::EscapesRoot(_))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn creates_only_guest_layout_directories() {
        let base = temporary_dir("layout");
        let root = RootFs::open(base.join("root")).unwrap();
        root.initialize_layout().unwrap();
        for name in ["system", "data", "dev", "proc", "sys", "tmp"] {
            assert!(root.root().join(name).is_dir(), "missing /{name}");
        }
        let _ = fs::remove_dir_all(base);
    }
}
