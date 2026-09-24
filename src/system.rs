#![allow(deprecated)]
//! System privilege checks, process single-instance locking, and directory helpers.

use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

use nix::fcntl::{flock, FlockArg};
use nix::unistd::Uid;

use crate::constants::LOCK_FILE;
use crate::error::{Result, UmbraError};

/// Scoped file lock guard that releases the lock upon dropping
pub struct ProcessLock {
    file: File,
}

impl ProcessLock {
    /// Attempts to acquire an exclusive non-blocking lock on /run/umbra/umbra.lock
    #[allow(deprecated)]
    pub fn acquire() -> Result<Self> {
        let lock_path = Path::new(LOCK_FILE);

        if let Some(parent) = lock_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    UmbraError::LockAcquisitionFailed(format!(
                        "failed to create runtime directory {}: {e}",
                        parent.display()
                    ))
                })?;
                let mut perms = fs::metadata(parent)
                    .map_err(|e| UmbraError::LockAcquisitionFailed(e.to_string()))?
                    .permissions();
                perms.set_mode(0o700);
                let _ = fs::set_permissions(parent, perms);
            }
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .map_err(|e| {
                UmbraError::LockAcquisitionFailed(format!(
                    "failed to open lock file {}: {e}",
                    lock_path.display()
                ))
            })?;

        // Non-blocking exclusive lock
        flock(file.as_raw_fd(), FlockArg::LockExclusiveNonblock).map_err(|e| {
            UmbraError::LockAcquisitionFailed(format!(
                "another Umbra instance is currently running or holding the lock ({e})"
            ))
        })?;

        Ok(Self { file })
    }
}

impl Drop for ProcessLock {
    #[allow(deprecated)]
    fn drop(&mut self) {
        let _ = flock(self.file.as_raw_fd(), FlockArg::Unlock);
    }
}

/// Verifies that the effective user ID is root (0)
pub fn require_root(operation: &str) -> Result<()> {
    if !Uid::effective().is_root() {
        return Err(UmbraError::PrivilegeRequired(operation.to_string()));
    }
    Ok(())
}
