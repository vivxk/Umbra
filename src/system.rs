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
#[derive(Debug)]
pub struct ProcessLock {
    file: File,
}

impl ProcessLock {
    /// Attempts to acquire an exclusive non-blocking lock on /run/umbra/umbra.lock
    #[allow(deprecated)]
    pub fn acquire() -> Result<Self> {
        Self::acquire_path(Path::new(LOCK_FILE))
    }

    /// Attempts to acquire an exclusive non-blocking lock on a specified path
    #[allow(deprecated)]
    pub fn acquire_path(lock_path: &Path) -> Result<Self> {
        if let Some(parent) = lock_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
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

    /// Removes the lock file at the specified path if present
    pub fn cleanup_path(path: &Path) -> Result<()> {
        if path.exists() {
            let _ = fs::remove_file(path);
        }
        Ok(())
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

/// Standard trusted system binary paths in order of preference
pub const TRUSTED_BIN_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// Resolves a command to an absolute path within trusted root-owned system directories,
/// verifying that the executable is owned by root, is not group/world-writable, and is executable.
pub fn resolve_trusted_command(binary: &str) -> Result<std::process::Command> {
    for &dir in TRUSTED_BIN_DIRS {
        let candidate = Path::new(dir).join(binary);
        if candidate.exists() {
            let canonical = fs::canonicalize(&candidate).map_err(|e| {
                UmbraError::TrustedBinaryNotFound(format!(
                    "failed to resolve canonical path for {}: {e}",
                    candidate.display()
                ))
            })?;

            // Must reside within a trusted prefix
            let in_trusted = TRUSTED_BIN_DIRS
                .iter()
                .any(|prefix| canonical.starts_with(Path::new(prefix)));
            if !in_trusted {
                continue;
            }

            let meta = fs::metadata(&canonical).map_err(|e| {
                UmbraError::TrustedBinaryNotFound(format!(
                    "cannot read metadata for {}: {e}",
                    canonical.display()
                ))
            })?;

            use std::os::unix::fs::MetadataExt;
            if !meta.is_file() {
                continue;
            }
            if meta.uid() != 0 {
                return Err(UmbraError::TrustedBinaryNotFound(format!(
                    "trusted binary {} is owned by UID {}, expected UID 0 (root)",
                    canonical.display(),
                    meta.uid()
                )));
            }
            let mode = meta.mode();
            if (mode & 0o022) != 0 {
                return Err(UmbraError::TrustedBinaryNotFound(format!(
                    "trusted binary {} has insecure permissions (mode {:04o}): group- or world-writable",
                    canonical.display(),
                    mode & 0o7777
                )));
            }
            if (mode & 0o111) == 0 {
                return Err(UmbraError::TrustedBinaryNotFound(format!(
                    "binary {} is not executable (mode {:04o})",
                    canonical.display(),
                    mode & 0o7777
                )));
            }

            return Ok(std::process::Command::new(canonical));
        }
    }

    Err(UmbraError::TrustedBinaryNotFound(format!(
        "command '{binary}' was not found in trusted system directories ({:?})",
        TRUSTED_BIN_DIRS
    )))
}

/// Detects whether the application is running inside a WSL (Windows Subsystem for Linux) environment
pub fn is_wsl_environment() -> bool {
    if let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
        let r = release.to_lowercase();
        if r.contains("microsoft") || r.contains("wsl") {
            return true;
        }
    }
    if let Ok(version) = std::fs::read_to_string("/proc/version") {
        let v = version.to_lowercase();
        if v.contains("microsoft") || v.contains("wsl") {
            return true;
        }
    }
    false
}
