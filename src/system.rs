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

/// Authorized system installation prefixes for the uninstaller script
pub const TRUSTED_UNINSTALL_PREFIXES: &[&str] = &["/usr/share/umbra", "/usr/local/share/umbra"];

/// Standard authorized script paths for uninstallation
pub const TRUSTED_UNINSTALL_SCRIPT_PATHS: &[&str] = &[
    "/usr/share/umbra/scripts/uninstall.sh",
    "/usr/local/share/umbra/scripts/uninstall.sh",
    "/usr/share/umbra/uninstall.sh",
    "/usr/local/share/umbra/uninstall.sh",
];

/// Validates that an uninstaller script is a trusted, root-owned, non-group/world-writable,
/// executable regular file residing strictly within an authorized system installation prefix.
pub fn validate_trusted_uninstall_script(script_path: &Path) -> Result<std::path::PathBuf> {
    if !script_path.exists() {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script does not exist: {}",
            script_path.display()
        )));
    }

    let canonical = fs::canonicalize(script_path).map_err(|e| {
        UmbraError::UninstallationFailed(format!(
            "failed to canonicalize uninstall script path {}: {e}",
            script_path.display()
        ))
    })?;

    // Must reside strictly within an authorized trusted prefix
    let in_trusted = TRUSTED_UNINSTALL_PREFIXES
        .iter()
        .any(|prefix| canonical.starts_with(Path::new(prefix)));
    if !in_trusted {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script {} does not reside in trusted system directories ({:?})",
            canonical.display(),
            TRUSTED_UNINSTALL_PREFIXES
        )));
    }

    let meta = fs::metadata(&canonical).map_err(|e| {
        UmbraError::UninstallationFailed(format!(
            "failed to read metadata for uninstall script {}: {e}",
            canonical.display()
        ))
    })?;

    use std::os::unix::fs::MetadataExt;
    if !meta.is_file() {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script {} is not a regular file",
            canonical.display()
        )));
    }

    // Must be owned by root (UID 0)
    if meta.uid() != 0 {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script {} must be owned by root (UID 0), found UID {}",
            canonical.display(),
            meta.uid()
        )));
    }

    let mode = meta.mode();
    // Must NOT be group-writable or world-writable
    if (mode & 0o022) != 0 {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script {} has insecure permissions (mode {:04o}): group- or world-writable",
            canonical.display(),
            mode & 0o7777
        )));
    }

    // Must be executable
    if (mode & 0o111) == 0 {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script {} is not executable (mode {:04o})",
            canonical.display(),
            mode & 0o7777
        )));
    }

    Ok(canonical)
}

/// Locates and verifies the legitimate installed Umbra uninstaller.
/// Strictly rejects arbitrary environment overrides and current working directory paths.
pub fn find_uninstall_script() -> Result<std::path::PathBuf> {
    for &candidate in TRUSTED_UNINSTALL_SCRIPT_PATHS {
        let path = Path::new(candidate);
        if path.exists() {
            return validate_trusted_uninstall_script(path);
        }
    }

    Err(UmbraError::UninstallationFailed(
        "installed uninstallation script not found in trusted system directories (/usr/share/umbra/scripts/uninstall.sh)".to_string(),
    ))
}

/// Executes uninstallation by delegating directly to the verified installed uninstall script
pub fn execute_uninstall() -> Result<()> {
    let script = find_uninstall_script()?;
    execute_uninstall_script(&script)
}

/// Delegates uninstallation execution to a specified script path using trusted bash
pub fn execute_uninstall_script(script_path: &Path) -> Result<()> {
    if !script_path.is_file() {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script does not exist or is not a regular file: {}",
            script_path.display()
        )));
    }

    let canonical = fs::canonicalize(script_path).map_err(|e| {
        UmbraError::UninstallationFailed(format!(
            "failed to canonicalize uninstall script path {}: {e}",
            script_path.display()
        ))
    })?;

    let meta = fs::metadata(&canonical).map_err(|e| {
        UmbraError::UninstallationFailed(format!(
            "failed to read metadata for uninstall script {}: {e}",
            canonical.display()
        ))
    })?;

    use std::os::unix::fs::MetadataExt;
    if !meta.is_file() {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script {} is not a regular file",
            canonical.display()
        )));
    }

    // Must not be world-writable
    if (meta.mode() & 0o002) != 0 {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script {} is world-writable",
            canonical.display()
        )));
    }

    let mut cmd = resolve_trusted_command("bash")?;
    cmd.arg(&canonical);
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let status = cmd.status().map_err(|e| {
        UmbraError::UninstallationFailed(format!(
            "failed to execute uninstallation script {}: {e}",
            canonical.display()
        ))
    })?;

    if !status.success() {
        return Err(UmbraError::UninstallationFailed(format!(
            "uninstall script failed with status {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "terminated by signal".to_string())
        )));
    }

    Ok(())
}
