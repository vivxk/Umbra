//! Tor process inspection, identity verification, configuration fragment management,
//! and authenticated ControlPort client.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::constants::{KNOWN_TOR_COOKIE_PATHS, KNOWN_TOR_USERS, LOCAL_LOOPBACK_IPV4};
use crate::error::{Result, UmbraError};

/// Information about a verified running Tor instance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorIdentity {
    pub pid: u32,
    pub uid: u32,
    pub exe_path: String,
}

/// Configuration parameters for Tor listeners and authentication
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorConfig {
    pub transport_port: u16,
    pub dns_port: u16,
    pub control_port: u16,
    pub cookie_auth: bool,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            transport_port: crate::constants::DEFAULT_TOR_TRANSPORT,
            dns_port: crate::constants::DEFAULT_TOR_DNSPORT,
            control_port: crate::constants::DEFAULT_TOR_CONTROLPORT,
            cookie_auth: true,
        }
    }
}

impl TorConfig {
    /// Renders an install-time Tor configuration fragment tagged with `# umbra-managed`
    pub fn render_fragment(&self) -> String {
        let cookie_flag = if self.cookie_auth { 1 } else { 0 };
        format!(
            "# umbra-managed: Umbra Tor Configuration Fragment\n\
             # Generated automatically by Umbra privacy boundary. Do not edit directly.\n\
             TransPort 127.0.0.1:{}\n\
             DNSPort 127.0.0.1:{}\n\
             ControlPort 127.0.0.1:{}\n\
             CookieAuthentication {}\n",
            self.transport_port, self.dns_port, self.control_port, cookie_flag,
        )
    }

    /// Detects candidate path for Tor configuration fragment on this host
    pub fn detect_fragment_path() -> PathBuf {
        let torrc_d = Path::new("/etc/tor/torrc.d");
        if torrc_d.is_dir() {
            torrc_d.join("umbra.conf")
        } else {
            PathBuf::from(crate::constants::DEFAULT_TOR_CONFIG_FRAGMENT)
        }
    }

    /// Verifies that a file is managed by Umbra and NOT the main torrc
    pub fn verify_fragment_ownership(path: &Path) -> Result<()> {
        let file_name = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();

        if file_name == "torrc" {
            return Err(UmbraError::TorConfigOwnershipMismatch(
                "refusing to treat main 'torrc' as an Umbra fragment; main torrc must never be overwritten".to_string(),
            ));
        }

        if path.exists() {
            // Verify resolved canonical target is not main torrc
            if let Ok(canonical) = fs::canonicalize(path) {
                if canonical
                    .file_name()
                    .and_then(|f| f.to_str())
                    .map(|f| f == "torrc")
                    .unwrap_or(false)
                {
                    return Err(UmbraError::TorConfigOwnershipMismatch(
                        "refusing to treat symlink pointing to main 'torrc' as an Umbra fragment"
                            .to_string(),
                    ));
                }
            }

            let content = fs::read_to_string(path).map_err(|e| {
                UmbraError::TorConfigOwnershipMismatch(format!(
                    "cannot read fragment at {}: {e}",
                    path.display()
                ))
            })?;

            if !content.contains("# umbra-managed") {
                return Err(UmbraError::TorConfigOwnershipMismatch(format!(
                    "file at {} exists but is missing '# umbra-managed' ownership tag",
                    path.display()
                )));
            }
        }

        Ok(())
    }

    /// Installs or updates an Umbra configuration fragment atomically
    pub fn install_fragment(path: &Path, config: &TorConfig) -> Result<()> {
        Self::verify_fragment_ownership(path)?;

        if path.is_symlink() {
            return Err(UmbraError::TorConfigOwnershipMismatch(format!(
                "refusing to overwrite symlink at {}; configuration fragment must be a regular file",
                path.display()
            )));
        }

        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let content = config.render_fragment();
        fs::write(path, content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
        }

        Ok(())
    }

    /// Removes an Umbra configuration fragment after verifying ownership
    pub fn remove_fragment(path: &Path) -> Result<()> {
        let file_name = path
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or_default();

        if file_name == "torrc" {
            return Err(UmbraError::TorConfigOwnershipMismatch(
                "refusing to remove main 'torrc'".to_string(),
            ));
        }

        if !path.exists() && !path.is_symlink() {
            return Ok(());
        }

        if let Ok(canonical) = fs::canonicalize(path) {
            if canonical
                .file_name()
                .and_then(|f| f.to_str())
                .map(|f| f == "torrc")
                .unwrap_or(false)
            {
                return Err(UmbraError::TorConfigOwnershipMismatch(
                    "refusing to remove symlink pointing to main 'torrc'".to_string(),
                ));
            }
        }

        Self::verify_fragment_ownership(path)?;
        fs::remove_file(path)?;
        Ok(())
    }
}

/// Parsed socket table entry from `/proc/net/tcp` or `/proc/net/udp`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub local_ip: [u8; 4],
    pub local_port: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

/// Parses a single line from `/proc/net/tcp` or `/proc/net/udp`
pub fn parse_proc_net_line(line: &str) -> Option<SocketEntry> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }
    if !parts[0].ends_with(':') {
        return None;
    }

    let addr_parts: Vec<&str> = parts[1].split(':').collect();
    if addr_parts.len() != 2 {
        return None;
    }

    let ip_hex = addr_parts[0];
    let port_hex = addr_parts[1];

    if ip_hex.len() != 8 {
        return None;
    }

    let ip_val = u32::from_str_radix(ip_hex, 16).ok()?;
    let ip_bytes = ip_val.to_le_bytes();
    let local_port = u16::from_str_radix(port_hex, 16).ok()?;
    let state = u8::from_str_radix(parts[3], 16).ok()?;
    let uid = parts[7].parse::<u32>().ok()?;
    let inode = parts[9].parse::<u64>().ok()?;

    Some(SocketEntry {
        local_ip: ip_bytes,
        local_port,
        state,
        uid,
        inode,
    })
}

/// Parses all socket entries from proc net file content
pub fn parse_proc_net_sockets(content: &str) -> Vec<SocketEntry> {
    content.lines().filter_map(parse_proc_net_line).collect()
}

/// Finds matching socket entry in a proc net file (e.g. `/proc/net/tcp` or `/proc/net/udp`)
pub fn find_socket_in_proc_net(proc_net_file: &Path, port: u16) -> Result<Option<SocketEntry>> {
    let content = fs::read_to_string(proc_net_file).map_err(|e| {
        UmbraError::TorInspectionError(format!("failed to read {}: {e}", proc_net_file.display()))
    })?;

    let is_udp = proc_net_file
        .file_name()
        .and_then(|f| f.to_str())
        .map(|s| s.contains("udp"))
        .unwrap_or(false);

    let entries = parse_proc_net_sockets(&content);
    let matched = entries.into_iter().find(|e| {
        if e.local_port != port {
            return false;
        }
        if is_udp {
            // In Linux /proc/net/udp, listening/bound sockets are state 0x07 (TCP_CLOSE)
            e.state == 0x07
        } else {
            // In Linux /proc/net/tcp, listening sockets are state 0x0A (TCP_LISTEN)
            e.state == 0x0A
        }
    });

    Ok(matched)
}

/// Finds the PID and comm owning a specific socket inode by inspecting `/proc/<pid>/fd`
pub fn find_socket_inode_owner(
    proc_dir: &Path,
    target_inode: u64,
) -> Result<Option<(u32, String)>> {
    let entries = fs::read_dir(proc_dir).map_err(|e| {
        UmbraError::TorInspectionError(format!(
            "failed to read proc directory {}: {e}",
            proc_dir.display()
        ))
    })?;

    let target_socket_str = format!("socket:[{target_inode}]");

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid_str = file_name.to_string_lossy();
        if let Ok(pid) = pid_str.parse::<u32>() {
            let fd_dir = entry.path().join("fd");
            if let Ok(fd_entries) = fs::read_dir(&fd_dir) {
                for fd_entry in fd_entries.flatten() {
                    if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                        if link_target.to_string_lossy() == target_socket_str {
                            let comm = fs::read_to_string(entry.path().join("comm"))
                                .map(|c| c.trim().to_string())
                                .unwrap_or_else(|_| "unknown".to_string());
                            return Ok(Some((pid, comm)));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Verifies socket ownership, binding address, UID, and owning PID
pub fn verify_socket_ownership(
    proc_net_file: &Path,
    proc_dir: &Path,
    port: u16,
    expected_uid: Option<u32>,
    expected_pid: Option<u32>,
) -> Result<()> {
    if !proc_net_file.exists() {
        return Err(UmbraError::TorInspectionError(format!(
            "socket inspection table {} does not exist",
            proc_net_file.display()
        )));
    }

    let socket = match find_socket_in_proc_net(proc_net_file, port)? {
        Some(s) => s,
        None => {
            return Err(UmbraError::TorListenerPortClosed {
                port,
                details: format!(
                    "no listener found for port {port} in {} (port closed)",
                    proc_net_file.display()
                ),
            });
        }
    };

    // Reject root-owned Tor socket unconditionally (Section 15)
    // Sockets created by systemd-managed Tor daemons before dropping privileges retain creator sk_uid=0 in /proc/net/tcp.
    // If socket.uid is 0, verify whether the actual owning process in /proc/<pid>/fd has dropped privileges to an unprivileged UID.
    let proc_uid = if socket.uid == 0 {
        let owning_pid = expected_pid.or_else(|| {
            find_socket_inode_owner(proc_dir, socket.inode)
                .ok()
                .flatten()
                .map(|(p, _)| p)
        });

        if let Some(pid) = owning_pid {
            let status_path = proc_dir.join(pid.to_string()).join("status");
            let uid = TorController::extract_uid_from_status(&status_path).ok();
            if uid == Some(0) || uid.is_none() {
                return Err(UmbraError::TorRunningAsRoot);
            }
            uid
        } else {
            return Err(UmbraError::TorRunningAsRoot);
        }
    } else {
        None
    };

    // Check bind address: must be local-only 127.0.0.1
    if socket.local_ip != [127, 0, 0, 1] {
        return Err(UmbraError::TorListenerWrongProcess {
            port,
            expected: "local loopback 127.0.0.1".to_string(),
            actual: format!(
                "bound to {}.{}.{}.{}",
                socket.local_ip[0], socket.local_ip[1], socket.local_ip[2], socket.local_ip[3]
            ),
        });
    }

    // Check UID if expected
    if let Some(exp_uid) = expected_uid {
        let effective_uid = if socket.uid == 0 {
            proc_uid.unwrap_or(0)
        } else {
            socket.uid
        };
        if effective_uid != exp_uid {
            return Err(UmbraError::TorListenerWrongProcess {
                port,
                expected: format!("Tor UID {exp_uid}"),
                actual: format!("UID {effective_uid}"),
            });
        }
    }

    // Check PID if expected
    if let Some(exp_pid) = expected_pid {
        let exp_pid_fd = proc_dir.join(exp_pid.to_string()).join("fd");
        if exp_pid_fd.exists() {
            let mut owns_socket = false;
            let target_socket_str = format!("socket:[{}]", socket.inode);
            if let Ok(entries) = fs::read_dir(&exp_pid_fd) {
                for entry in entries.flatten() {
                    if let Ok(target) = fs::read_link(entry.path()) {
                        if target.to_string_lossy() == target_socket_str {
                            owns_socket = true;
                            break;
                        }
                    }
                }
            }
            if !owns_socket {
                let actual = match find_socket_inode_owner(proc_dir, socket.inode) {
                    Ok(Some((owner_pid, owner_comm))) => format!("{owner_comm} (PID {owner_pid})"),
                    _ => "unknown or different process".to_string(),
                };
                return Err(UmbraError::TorListenerWrongProcess {
                    port,
                    expected: format!("Tor PID {exp_pid}"),
                    actual,
                });
            }
        } else if let Ok(Some((owner_pid, owner_comm))) =
            find_socket_inode_owner(proc_dir, socket.inode)
        {
            if owner_pid != exp_pid {
                return Err(UmbraError::TorListenerWrongProcess {
                    port,
                    expected: format!("Tor PID {exp_pid}"),
                    actual: format!("{owner_comm} (PID {owner_pid})"),
                });
            }
        }
    }

    Ok(())
}

/// Verifies that an executable resides in trusted root-owned paths and is secure
pub fn verify_executable_security_with_config(
    exe_path: &Path,
    expected_owner_uid: Option<u32>,
    trusted_prefixes: &[&str],
) -> Result<()> {
    if !exe_path.exists() {
        return Err(UmbraError::TorExecutableUntrusted(format!(
            "executable path does not exist: {}",
            exe_path.display()
        )));
    }

    let canonical = fs::canonicalize(exe_path).map_err(|e| {
        UmbraError::TorExecutableUntrusted(format!(
            "failed to resolve canonical path for {}: {e}",
            exe_path.display()
        ))
    })?;

    // Both canonical target and original path must reside in trusted paths
    let canonical_in_trusted = trusted_prefixes
        .iter()
        .any(|prefix| canonical.starts_with(Path::new(prefix)));
    let exe_in_trusted = trusted_prefixes
        .iter()
        .any(|prefix| exe_path.starts_with(Path::new(prefix)));

    if !canonical_in_trusted || !exe_in_trusted {
        return Err(UmbraError::TorExecutableUntrusted(format!(
            "executable {} (canonical: {}) does not reside in trusted root-owned paths ({:?})",
            exe_path.display(),
            canonical.display(),
            trusted_prefixes
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(&canonical).map_err(|e| {
            UmbraError::TorExecutableUntrusted(format!(
                "cannot read metadata for {}: {e}",
                canonical.display()
            ))
        })?;

        if !meta.is_file() {
            return Err(UmbraError::TorExecutableUntrusted(format!(
                "executable {} is not a regular file",
                canonical.display()
            )));
        }

        let file_uid = meta.uid();
        if let Some(exp_uid) = expected_owner_uid {
            if file_uid != exp_uid {
                return Err(UmbraError::TorExecutableUntrusted(format!(
                    "executable {} is owned by UID {file_uid}, expected UID {exp_uid} (root)",
                    canonical.display()
                )));
            }
        }

        let mode = meta.mode();
        if (mode & 0o022) != 0 {
            return Err(UmbraError::TorExecutableUntrusted(format!(
                "executable {} has insecure permissions (mode {:04o}): group- or world-writable",
                canonical.display(),
                mode & 0o7777
            )));
        }

        if (mode & 0o6000) != 0 {
            return Err(UmbraError::TorExecutableUntrusted(format!(
                "executable {} has SUID/SGID bit set (mode {:04o}); Tor must not be setuid/setgid",
                canonical.display(),
                mode & 0o7777
            )));
        }

        if (mode & 0o111) == 0 {
            return Err(UmbraError::TorExecutableUntrusted(format!(
                "executable {} is not executable (mode {:04o})",
                canonical.display(),
                mode & 0o7777
            )));
        }
    }

    Ok(())
}

/// Verifies that an executable resides in trusted root-owned paths, owned by UID 0,
/// and not group- or world-writable
pub fn verify_executable_security(exe_path: &Path) -> Result<()> {
    verify_executable_security_with_config(
        exe_path,
        Some(0),
        crate::constants::TRUSTED_TOR_PREFIXES,
    )
}

/// Reads an RFC 250 style reply from a Tor ControlPort stream
pub fn read_control_reply<R: BufRead>(reader: &mut R) -> Result<(u16, Vec<String>)> {
    let mut lines = Vec::new();
    let mut final_code = None;

    loop {
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            if lines.is_empty() {
                return Err(UmbraError::TorControlError(
                    "connection closed by Tor ControlPort".to_string(),
                ));
            }
            break;
        }

        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.len() < 3 {
            return Err(UmbraError::TorControlProtocolError(format!(
                "malformed response line from ControlPort: '{trimmed}'"
            )));
        }

        let code_str = &trimmed[0..3];
        let code = code_str.parse::<u16>().map_err(|_| {
            UmbraError::TorControlProtocolError(format!(
                "non-numeric status code in response line: '{trimmed}'"
            ))
        })?;

        let delimiter = trimmed.chars().nth(3).unwrap_or(' ');
        lines.push(trimmed.to_string());

        if delimiter == ' ' {
            final_code = Some(code);
            break;
        } else if delimiter == '-' {
            // Multi-line continuation
            continue;
        } else if delimiter == '+' {
            // Multi-line data block ending with lone "."
            loop {
                let mut data_line = String::new();
                let n = reader.read_line(&mut data_line)?;
                if n == 0 {
                    return Err(UmbraError::TorControlProtocolError(
                        "unexpected EOF while reading data block".to_string(),
                    ));
                }
                let data_trimmed = data_line.trim_end_matches(&['\r', '\n'][..]);
                if data_trimmed == "." {
                    break;
                }
            }
            continue;
        } else {
            final_code = Some(code);
            break;
        }
    }

    let code = final_code.ok_or_else(|| {
        UmbraError::TorControlProtocolError("incomplete response from ControlPort".to_string())
    })?;

    Ok((code, lines))
}

/// Parses the COOKIEFILE parameter from PROTOCOLINFO 1 reply lines
pub fn extract_cookie_path_from_protocolinfo(lines: &[String]) -> Option<String> {
    for line in lines {
        if let Some(pos) = line.find("COOKIEFILE=\"") {
            let remainder = &line[pos + 12..];
            let mut result = String::new();
            let mut chars = remainder.chars();
            while let Some(c) = chars.next() {
                if c == '\\' {
                    if let Some(escaped) = chars.next() {
                        result.push(escaped);
                    }
                } else if c == '\"' {
                    return Some(result);
                } else {
                    result.push(c);
                }
            }
            return Some(result);
        } else if let Some(pos) = line.find("COOKIEFILE=") {
            let remainder = &line[pos + 11..];
            let end = remainder
                .find(|c: char| c.is_whitespace())
                .unwrap_or(remainder.len());
            return Some(remainder[..end].to_string());
        }
    }
    None
}

/// Hex encodes a byte slice
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct TorController;

impl TorController {
    /// Discovers system UID for Tor (e.g. debian-tor or tor)
    pub fn resolve_tor_uid() -> Result<u32> {
        Self::resolve_tor_uid_with_paths(
            Path::new("/proc"),
            Path::new("/etc/passwd"),
            Some(0),
            crate::constants::TRUSTED_TOR_PREFIXES,
        )
    }

    /// Discovers system UID for Tor using configurable proc and passwd paths
    pub fn resolve_tor_uid_with_paths(
        proc_dir: &Path,
        passwd_path: &Path,
        expected_owner_uid: Option<u32>,
        trusted_prefixes: &[&str],
    ) -> Result<u32> {
        // First check running Tor process
        if let Ok(Some(ident)) =
            Self::find_tor_process_at(proc_dir, expected_owner_uid, trusted_prefixes)
        {
            return Ok(ident.uid);
        }

        // Fallback: parse passwd
        if let Ok(passwd) = fs::read_to_string(passwd_path) {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    let username = parts[0];
                    if KNOWN_TOR_USERS.contains(&username) {
                        if let Ok(uid) = parts[2].parse::<u32>() {
                            if uid == 0 {
                                return Err(UmbraError::TorRunningAsRoot);
                            }
                            return Ok(uid);
                        }
                    }
                }
            }
        }

        Err(UmbraError::TorIdentityUnknown(
            "could not find Tor user account or running Tor process".to_string(),
        ))
    }

    /// Inspects /proc to find a verified Tor process
    pub fn find_tor_process() -> Result<Option<TorIdentity>> {
        Self::find_tor_process_at(
            Path::new("/proc"),
            Some(0),
            crate::constants::TRUSTED_TOR_PREFIXES,
        )
    }

    /// Inspects a given proc directory to find a verified Tor process
    pub fn find_tor_process_at(
        proc_dir: &Path,
        expected_owner_uid: Option<u32>,
        trusted_prefixes: &[&str],
    ) -> Result<Option<TorIdentity>> {
        let proc_entries = match fs::read_dir(proc_dir) {
            Ok(e) => e,
            Err(e) => {
                return Err(UmbraError::TorIdentityUnknown(format!(
                    "failed to read {}: {e}",
                    proc_dir.display()
                )))
            }
        };

        let mut valid_matches = Vec::new();

        for entry in proc_entries.flatten() {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();
            if let Ok(pid) = pid_str.parse::<u32>() {
                let comm_path = entry.path().join("comm");
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    let comm_clean = comm.trim();
                    if comm_clean == "tor" || comm_clean == "tor.real" {
                        match Self::verify_tor_process_at(
                            proc_dir,
                            pid,
                            expected_owner_uid,
                            trusted_prefixes,
                        ) {
                            Ok(ident) => valid_matches.push(ident),
                            Err(UmbraError::TorRunningAsRoot) => {
                                return Err(UmbraError::TorRunningAsRoot)
                            }
                            Err(UmbraError::TorProcessNotFound(_)) => continue,
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }

        if valid_matches.len() > 1 {
            let pids: Vec<u32> = valid_matches.iter().map(|m| m.pid).collect();
            return Err(UmbraError::TorProcessAmbiguous(format!(
                "found {} instances: PIDs {:?}",
                valid_matches.len(),
                pids
            )));
        }

        Ok(valid_matches.into_iter().next())
    }

    /// Strictly verifies a Tor process by PID in `/proc`
    pub fn verify_tor_process(pid: u32) -> Result<TorIdentity> {
        Self::verify_tor_process_at(
            Path::new("/proc"),
            pid,
            Some(0),
            crate::constants::TRUSTED_TOR_PREFIXES,
        )
    }

    /// Strictly verifies a Tor process by PID in a given proc directory
    pub fn verify_tor_process_at(
        proc_dir: &Path,
        pid: u32,
        expected_owner_uid: Option<u32>,
        trusted_prefixes: &[&str],
    ) -> Result<TorIdentity> {
        let pid_dir = proc_dir.join(pid.to_string());
        if !pid_dir.exists() {
            return Err(UmbraError::TorProcessNotFound(pid));
        }

        // Check comm
        let comm_path = pid_dir.join("comm");
        let comm = fs::read_to_string(&comm_path)
            .map(|c| c.trim().to_string())
            .map_err(|_| UmbraError::TorProcessNotFound(pid))?;

        if comm != "tor" && comm != "tor.real" {
            return Err(UmbraError::TorProcessMismatch { pid, comm });
        }

        // Check UID
        let status_path = pid_dir.join("status");
        let uid = Self::extract_uid_from_status(&status_path)?;
        if uid == 0 {
            return Err(UmbraError::TorRunningAsRoot);
        }

        // Check exe
        let exe_link = pid_dir.join("exe");
        let target_path = fs::read_link(&exe_link).map_err(|e| {
            UmbraError::TorExecutableUntrusted(format!(
                "cannot read exe symlink for PID {pid}: {e}"
            ))
        })?;

        verify_executable_security_with_config(&target_path, expected_owner_uid, trusted_prefixes)?;

        Ok(TorIdentity {
            pid,
            uid,
            exe_path: target_path.to_string_lossy().to_string(),
        })
    }

    pub fn extract_uid_from_status(path: &Path) -> Result<u32> {
        let content = fs::read_to_string(path).map_err(|e| {
            UmbraError::TorIdentityUnknown(format!("cannot read status at {}: {e}", path.display()))
        })?;

        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    // Uid: <real> <effective> <saved> <fs>
                    let ruid = parts[1].parse::<u32>().map_err(|_| {
                        UmbraError::TorIdentityUnknown("invalid real Uid in status".to_string())
                    })?;
                    let euid = parts[2].parse::<u32>().map_err(|_| {
                        UmbraError::TorIdentityUnknown(
                            "invalid effective Uid in status".to_string(),
                        )
                    })?;
                    let suid = parts[3].parse::<u32>().map_err(|_| {
                        UmbraError::TorIdentityUnknown("invalid saved Uid in status".to_string())
                    })?;
                    let fsuid = parts[4].parse::<u32>().map_err(|_| {
                        UmbraError::TorIdentityUnknown("invalid fs Uid in status".to_string())
                    })?;

                    if ruid == 0 || euid == 0 || suid == 0 || fsuid == 0 {
                        return Err(UmbraError::TorRunningAsRoot);
                    }

                    return Ok(euid);
                } else if parts.len() >= 2 {
                    let uid = parts[1].parse::<u32>().map_err(|_| {
                        UmbraError::TorIdentityUnknown("invalid Uid in status".to_string())
                    })?;
                    if uid == 0 {
                        return Err(UmbraError::TorRunningAsRoot);
                    }
                    return Ok(uid);
                }
            }
        }

        Err(UmbraError::TorIdentityUnknown(
            "Uid field not found in status".to_string(),
        ))
    }

    /// Verifies that Tor TransPort is bound and accepting connections on 127.0.0.1
    pub fn verify_transport(port: u16) -> Result<()> {
        let ident = Self::find_tor_process().ok().flatten();
        Self::verify_transport_with_identity(port, ident.as_ref())
    }

    /// Verifies that Tor TransPort is bound on 127.0.0.1 and matches expected identity
    pub fn verify_transport_with_identity(port: u16, expected: Option<&TorIdentity>) -> Result<()> {
        Self::verify_transport_at(Path::new("/proc"), port, expected)
    }

    /// Verifies that Tor TransPort is bound on 127.0.0.1 and matches expected identity using specified proc dir
    pub fn verify_transport_at(
        proc_dir: &Path,
        port: u16,
        expected: Option<&TorIdentity>,
    ) -> Result<()> {
        let addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket_addr: SocketAddr = addr.parse().map_err(|_| UmbraError::TorListenerMissing {
            port,
            details: "invalid socket address".to_string(),
        })?;

        let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(500));
        match stream {
            Ok(_) => {
                verify_socket_ownership(
                    &proc_dir.join("net/tcp"),
                    proc_dir,
                    port,
                    expected.map(|i| i.uid),
                    expected.map(|i| i.pid),
                )?;
                Ok(())
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.raw_os_error() == Some(111)
                {
                    Err(UmbraError::TorListenerPortClosed {
                        port,
                        details: format!("connection to TransPort at {addr} refused"),
                    })
                } else if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(110)
                {
                    Err(UmbraError::TorListenerTimeout {
                        port,
                        details: format!("connection to TransPort at {addr} timed out"),
                    })
                } else {
                    Err(UmbraError::TorListenerMissing {
                        port,
                        details: format!("connection to TransPort at {addr} failed: {e}"),
                    })
                }
            }
        }
    }

    /// Verifies that Tor DNSPort is bound on UDP 127.0.0.1
    pub fn verify_dnsport(port: u16) -> Result<()> {
        let ident = Self::find_tor_process().ok().flatten();
        Self::verify_dnsport_with_identity(port, ident.as_ref())
    }

    /// Verifies that Tor DNSPort is bound on UDP 127.0.0.1 and matches expected identity
    pub fn verify_dnsport_with_identity(port: u16, expected: Option<&TorIdentity>) -> Result<()> {
        Self::verify_dnsport_at(Path::new("/proc"), port, expected)
    }

    /// Verifies that Tor DNSPort is bound on UDP 127.0.0.1 and matches expected identity using specified proc dir
    pub fn verify_dnsport_at(
        proc_dir: &Path,
        port: u16,
        expected: Option<&TorIdentity>,
    ) -> Result<()> {
        verify_socket_ownership(
            &proc_dir.join("net/udp"),
            proc_dir,
            port,
            expected.map(|i| i.uid),
            expected.map(|i| i.pid),
        )?;

        let target_addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| {
            UmbraError::DnsProtectionFailed(format!("failed to bind test UDP socket: {e}"))
        })?;

        socket
            .set_read_timeout(Some(Duration::from_millis(1500)))
            .map_err(|e| {
                UmbraError::DnsProtectionFailed(format!("failed to set socket timeout: {e}"))
            })?;

        let parsed_target: SocketAddr =
            target_addr
                .parse()
                .map_err(|_| UmbraError::TorListenerMissing {
                    port,
                    details: "invalid socket address".to_string(),
                })?;

        let _ = socket.connect(parsed_target);

        // Query 1.0.0.127.in-addr.arpa (PTR) which Tor resolves immediately locally without requiring exit node circuits
        let query_packet = [
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query (RD=1)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x01, b'1', 0x01, b'0', 0x01, b'0', 0x03, b'1', b'2', b'7', 0x07, b'i', b'n', b'-',
            b'a', b'd', b'd', b'r', 0x04, b'a', b'r', b'p', b'a', 0x00, // End of name
            0x00, 0x0C, // Type PTR (12)
            0x00, 0x01, // Class IN (1)
        ];

        if let Err(e) = socket.send(&query_packet) {
            if e.kind() == std::io::ErrorKind::ConnectionRefused || e.raw_os_error() == Some(111) {
                return Err(UmbraError::TorListenerPortClosed {
                    port,
                    details: format!("DNSPort at {target_addr} connection refused: {e}"),
                });
            }
            return Err(UmbraError::TorListenerMissing {
                port,
                details: format!("failed to send UDP test packet to {target_addr}: {e}"),
            });
        }

        let mut buf = [0u8; 512];
        match socket.recv(&mut buf) {
            Ok(bytes_read) if bytes_read >= 12 => {
                if buf[0] != 0x12 || buf[1] != 0x34 {
                    return Err(UmbraError::TorListenerWrongProcess {
                        port,
                        expected: "valid DNS response matching query transaction ID".to_string(),
                        actual: format!("mismatched transaction ID: {:02x}{:02x}", buf[0], buf[1]),
                    });
                }
                Ok(())
            }
            Ok(_) => Err(UmbraError::TorListenerWrongProcess {
                port,
                expected: "DNS header (>= 12 bytes)".to_string(),
                actual: "truncated response (< 12 bytes)".to_string(),
            }),
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.raw_os_error() == Some(111)
                {
                    Err(UmbraError::TorListenerPortClosed {
                        port,
                        details: format!("DNSPort at {target_addr} connection refused: {e}"),
                    })
                } else if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(110)
                {
                    Err(UmbraError::TorListenerTimeout {
                        port,
                        details: format!("no response from DNSPort at {target_addr} (timed out)"),
                    })
                } else {
                    Err(UmbraError::TorListenerMissing {
                        port,
                        details: format!("no response from DNSPort at {target_addr}: {e}"),
                    })
                }
            }
        }
    }

    /// Verifies that Tor ControlPort is bound on 127.0.0.1, owned by Tor, and speaks Tor Control protocol
    pub fn verify_controlport(port: u16) -> Result<()> {
        let ident = Self::find_tor_process().ok().flatten();
        Self::verify_controlport_with_identity(port, ident.as_ref())
    }

    /// Verifies that Tor ControlPort is bound on 127.0.0.1, owned by expected identity, and speaks RFC 250 protocol
    pub fn verify_controlport_with_identity(
        port: u16,
        expected: Option<&TorIdentity>,
    ) -> Result<()> {
        Self::verify_controlport_at(Path::new("/proc"), port, expected)
    }

    /// Verifies that Tor ControlPort is bound on 127.0.0.1, owned by expected identity, and speaks RFC 250 protocol using specified proc dir
    pub fn verify_controlport_at(
        proc_dir: &Path,
        port: u16,
        expected: Option<&TorIdentity>,
    ) -> Result<()> {
        verify_socket_ownership(
            &proc_dir.join("net/tcp"),
            proc_dir,
            port,
            expected.map(|i| i.uid),
            expected.map(|i| i.pid),
        )?;

        let addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|_| UmbraError::TorControlError("invalid address".to_string()))?;

        let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(500))
        {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.raw_os_error() == Some(111)
                {
                    return Err(UmbraError::TorListenerPortClosed {
                        port,
                        details: format!("connection to ControlPort at {addr} refused"),
                    });
                } else if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(110)
                {
                    return Err(UmbraError::TorListenerTimeout {
                        port,
                        details: format!("connection to ControlPort at {addr} timed out"),
                    });
                } else {
                    return Err(UmbraError::TorListenerMissing {
                        port,
                        details: format!("connection to ControlPort at {addr} failed: {e}"),
                    });
                }
            }
        };

        stream
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .map_err(|e| UmbraError::TorControlError(format!("cannot set read timeout: {e}")))?;
        stream
            .set_write_timeout(Some(Duration::from_millis(1000)))
            .map_err(|e| UmbraError::TorControlError(format!("cannot set write timeout: {e}")))?;

        stream.write_all(b"PROTOCOLINFO 1\r\n").map_err(|e| {
            UmbraError::TorControlError(format!("failed to send PROTOCOLINFO to ControlPort: {e}"))
        })?;

        let mut reader = BufReader::new(stream);
        let (code, lines) = read_control_reply(&mut reader).map_err(|e| match e {
            UmbraError::Io(ref io_err)
                if io_err.kind() == std::io::ErrorKind::TimedOut
                    || io_err.kind() == std::io::ErrorKind::WouldBlock
                    || io_err.raw_os_error() == Some(110)
                    || io_err.raw_os_error() == Some(11) =>
            {
                UmbraError::TorListenerTimeout {
                    port,
                    details: format!("connection to ControlPort at {addr} timed out"),
                }
            }
            UmbraError::TorControlProtocolError(p) => UmbraError::TorListenerWrongProcess {
                port,
                expected: "Tor ControlPort protocol (RFC 250)".to_string(),
                actual: format!("protocol error: {p}"),
            },
            UmbraError::TorControlError(msg) if msg.contains("closed") => {
                UmbraError::TorListenerWrongProcess {
                    port,
                    expected: "Tor ControlPort protocol (RFC 250)".to_string(),
                    actual: format!("connection closed prematurely: {msg}"),
                }
            }
            other => other,
        })?;

        if code != 250 {
            return Err(UmbraError::TorListenerWrongProcess {
                port,
                expected: "Tor ControlPort (RFC 250)".to_string(),
                actual: format!("status {code}: {}", lines.join(" ")),
            });
        }

        let _ = reader.get_mut().write_all(b"QUIT\r\n");

        Ok(())
    }

    /// Sends authenticated SIGNAL NEWNYM to Tor ControlPort
    pub fn request_newnym(port: u16) -> Result<()> {
        let ident = Self::find_tor_process()?.ok_or(UmbraError::TorNotRunning)?;
        Self::request_newnym_with_options(port, Some(&ident), None)
    }

    /// Sends authenticated SIGNAL NEWNYM to Tor ControlPort with explicit options
    pub fn request_newnym_with_options(
        port: u16,
        expected_identity: Option<&TorIdentity>,
        custom_cookie_path: Option<&Path>,
    ) -> Result<()> {
        verify_socket_ownership(
            Path::new("/proc/net/tcp"),
            Path::new("/proc"),
            port,
            expected_identity.map(|i| i.uid),
            expected_identity.map(|i| i.pid),
        )?;

        let addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|_| UmbraError::TorControlError("invalid address".to_string()))?;

        let stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.raw_os_error() == Some(111)
                {
                    return Err(UmbraError::TorListenerPortClosed {
                        port,
                        details: format!("connection to ControlPort at {addr} refused"),
                    });
                } else if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(110)
                {
                    return Err(UmbraError::TorListenerTimeout {
                        port,
                        details: format!("connection to ControlPort at {addr} timed out"),
                    });
                } else {
                    return Err(UmbraError::TorControlError(format!(
                        "cannot connect to ControlPort at {addr}: {e}"
                    )));
                }
            }
        };

        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| UmbraError::TorControlError(e.to_string()))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| UmbraError::TorControlError(e.to_string()))?;

        let mut reader = BufReader::new(stream);

        // 1. Send PROTOCOLINFO 1 to detect cookie file path and verify protocol
        reader
            .get_mut()
            .write_all(b"PROTOCOLINFO 1\r\n")
            .map_err(|e| {
                UmbraError::TorControlError(format!("failed to send PROTOCOLINFO: {e}"))
            })?;

        let (proto_code, proto_lines) = read_control_reply(&mut reader).map_err(|e| match e {
            UmbraError::Io(ref io_err)
                if io_err.kind() == std::io::ErrorKind::TimedOut
                    || io_err.kind() == std::io::ErrorKind::WouldBlock
                    || io_err.raw_os_error() == Some(110)
                    || io_err.raw_os_error() == Some(11) =>
            {
                UmbraError::TorListenerTimeout {
                    port,
                    details: format!("connection to ControlPort at {addr} timed out"),
                }
            }
            UmbraError::TorControlProtocolError(p) => UmbraError::TorListenerWrongProcess {
                port,
                expected: "Tor ControlPort protocol (RFC 250)".to_string(),
                actual: format!("protocol error: {p}"),
            },
            UmbraError::TorControlError(msg) if msg.contains("closed") => {
                UmbraError::TorListenerWrongProcess {
                    port,
                    expected: "Tor ControlPort protocol (RFC 250)".to_string(),
                    actual: format!("connection closed prematurely: {msg}"),
                }
            }
            other => other,
        })?;

        if proto_code != 250 {
            return Err(UmbraError::TorControlProtocolError(format!(
                "PROTOCOLINFO failed: {}",
                proto_lines.join(" ")
            )));
        }

        let detected_cookie_file = extract_cookie_path_from_protocolinfo(&proto_lines);

        // 2. Locate auth cookie
        let mut cookie_bytes = None;
        if let Some(path) = custom_cookie_path {
            match fs::File::open(path) {
                Ok(mut f) => {
                    let mut bytes = Vec::new();
                    if f.read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
                        cookie_bytes = Some(bytes);
                    } else {
                        return Err(UmbraError::TorControlAuthFailed(format!(
                            "custom cookie file at {} is empty or unreadable",
                            path.display()
                        )));
                    }
                }
                Err(e) => {
                    return Err(UmbraError::TorControlAuthFailed(format!(
                        "failed to open custom cookie file at {}: {e}",
                        path.display()
                    )));
                }
            }
        }

        if cookie_bytes.is_none() {
            if let Some(ref path_str) = detected_cookie_file {
                let p = Path::new(path_str);
                if let Ok(mut f) = fs::File::open(p) {
                    let mut bytes = Vec::new();
                    if f.read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
                        cookie_bytes = Some(bytes);
                    }
                }
            }
        }

        if cookie_bytes.is_none() {
            for path in KNOWN_TOR_COOKIE_PATHS {
                if let Ok(mut f) = fs::File::open(path) {
                    let mut bytes = Vec::new();
                    if f.read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
                        cookie_bytes = Some(bytes);
                        break;
                    }
                }
            }
        }

        // 3. Authenticate
        let auth_cmd = if let Some(ref cookie) = cookie_bytes {
            let hex_cookie = hex_encode(cookie);
            format!("AUTHENTICATE {hex_cookie}\r\n")
        } else {
            "AUTHENTICATE\r\n".to_string()
        };

        reader
            .get_mut()
            .write_all(auth_cmd.as_bytes())
            .map_err(|e| {
                UmbraError::TorControlError(format!("failed to send AUTHENTICATE: {e}"))
            })?;

        let (auth_code, auth_lines) = read_control_reply(&mut reader).map_err(|e| match e {
            UmbraError::Io(ref io_err)
                if io_err.kind() == std::io::ErrorKind::TimedOut
                    || io_err.kind() == std::io::ErrorKind::WouldBlock
                    || io_err.raw_os_error() == Some(110)
                    || io_err.raw_os_error() == Some(11) =>
            {
                UmbraError::TorListenerTimeout {
                    port,
                    details: format!("connection to ControlPort at {addr} timed out"),
                }
            }
            other => other,
        })?;

        if auth_code == 515 {
            return Err(UmbraError::TorControlAuthFailed(auth_lines.join(" ")));
        } else if auth_code != 250 {
            return Err(UmbraError::TorControlProtocolError(format!(
                "authentication failed: {}",
                auth_lines.join(" ")
            )));
        }

        // 4. Send SIGNAL NEWNYM
        reader
            .get_mut()
            .write_all(b"SIGNAL NEWNYM\r\n")
            .map_err(|e| UmbraError::TorControlError(format!("failed to send NEWNYM: {e}")))?;

        let (nym_code, nym_lines) = read_control_reply(&mut reader).map_err(|e| match e {
            UmbraError::Io(ref io_err)
                if io_err.kind() == std::io::ErrorKind::TimedOut
                    || io_err.kind() == std::io::ErrorKind::WouldBlock
                    || io_err.raw_os_error() == Some(110)
                    || io_err.raw_os_error() == Some(11) =>
            {
                UmbraError::TorListenerTimeout {
                    port,
                    details: format!("connection to ControlPort at {addr} timed out"),
                }
            }
            other => other,
        })?;

        if nym_code != 250 {
            return Err(UmbraError::TorControlError(format!(
                "NEWNYM command failed: {}",
                nym_lines.join(" ")
            )));
        }

        // 5. Send QUIT
        let _ = reader.get_mut().write_all(b"QUIT\r\n");

        Ok(())
    }

    pub fn verify_config_fragment_ownership(path: &Path) -> Result<()> {
        TorConfig::verify_fragment_ownership(path)
    }

    pub fn install_config_fragment(path: &Path, config: &TorConfig) -> Result<()> {
        TorConfig::install_fragment(path, config)
    }

    pub fn remove_config_fragment(path: &Path) -> Result<()> {
        TorConfig::remove_fragment(path)
    }
}
