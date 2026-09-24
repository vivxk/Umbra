//! Tor process inspection, identity verification, and authenticated ControlPort client.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::Duration;

use crate::constants::{KNOWN_TOR_USERS, LOCAL_LOOPBACK_IPV4};
use crate::error::{Result, UmbraError};

/// Information about a verified running Tor instance
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorIdentity {
    pub pid: u32,
    pub uid: u32,
    pub exe_path: String,
}

pub struct TorController;

impl TorController {
    /// Discovers system UID for Tor (e.g. debian-tor or tor)
    pub fn resolve_tor_uid() -> Result<u32> {
        // First check running Tor process if available
        if let Ok(Some(ident)) = Self::find_tor_process() {
            return Ok(ident.uid);
        }

        // Fallback: parse /etc/passwd for known Tor users
        if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
            for line in passwd.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 3 {
                    let username = parts[0];
                    if KNOWN_TOR_USERS.contains(&username) {
                        if let Ok(uid) = parts[2].parse::<u32>() {
                            if uid != 0 {
                                return Ok(uid);
                            }
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
        let proc_dir = fs::read_dir("/proc")
            .map_err(|e| UmbraError::TorIdentityUnknown(format!("failed to read /proc: {e}")))?;

        for entry in proc_dir.flatten() {
            let file_name = entry.file_name();
            let pid_str = file_name.to_string_lossy();
            if let Ok(pid) = pid_str.parse::<u32>() {
                let comm_path = entry.path().join("comm");
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    let comm_clean = comm.trim();
                    if comm_clean == "tor" || comm_clean == "tor.real" {
                        // Inspect exe target
                        let exe_link = entry.path().join("exe");
                        let target_path = fs::read_link(&exe_link)
                            .map(|p| p.to_string_lossy().to_string())
                            .unwrap_or_default();

                        // Verify UID from /proc/<pid>/status
                        let status_path = entry.path().join("status");
                        let uid = Self::extract_uid_from_status(&status_path)?;

                        if uid == 0 {
                            return Err(UmbraError::TorRunningAsRoot);
                        }

                        return Ok(Some(TorIdentity {
                            pid,
                            uid,
                            exe_path: target_path,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    fn extract_uid_from_status(path: &Path) -> Result<u32> {
        let content = fs::read_to_string(path).map_err(|e| {
            UmbraError::TorIdentityUnknown(format!("cannot read status at {}: {e}", path.display()))
        })?;

        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let real_uid = parts[1].parse::<u32>().map_err(|_| {
                        UmbraError::TorIdentityUnknown("invalid Uid field in status".to_string())
                    })?;
                    return Ok(real_uid);
                }
            }
        }

        Err(UmbraError::TorIdentityUnknown(
            "Uid field not found in status".to_string(),
        ))
    }

    /// Verifies that Tor TransPort is bound and accepting connections on 127.0.0.1
    pub fn verify_transport(port: u16) -> Result<()> {
        let addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket_addr: SocketAddr = addr.parse().map_err(|_| UmbraError::TorListenerMissing {
            port,
            details: "invalid socket address".to_string(),
        })?;

        let stream = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(500));
        match stream {
            Ok(_) => Ok(()),
            Err(e) => Err(UmbraError::TorListenerMissing {
                port,
                details: format!("connection to TransPort at {addr} failed: {e}"),
            }),
        }
    }

    /// Verifies that Tor DNSPort is bound on UDP 127.0.0.1
    pub fn verify_dnsport(port: u16) -> Result<()> {
        let target_addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| {
            UmbraError::DnsProtectionFailed(format!("failed to bind test UDP socket: {e}"))
        })?;

        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| {
                UmbraError::DnsProtectionFailed(format!("failed to set socket timeout: {e}"))
            })?;

        // Minimal DNS query for "localhost" A record
        let query_packet = [
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            0x09, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x00, // Name
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        socket.send_to(&query_packet, &target_addr).map_err(|e| {
            UmbraError::TorListenerMissing {
                port,
                details: format!("failed to send UDP test packet to {target_addr}: {e}"),
            }
        })?;

        let mut buf = [0u8; 512];
        match socket.recv_from(&mut buf) {
            Ok((bytes_read, _src)) if bytes_read > 0 => Ok(()),
            Ok(_) => Err(UmbraError::TorListenerMissing {
                port,
                details: "received 0 bytes from DNSPort".to_string(),
            }),
            Err(e) => Err(UmbraError::TorListenerMissing {
                port,
                details: format!("no response from DNSPort at {target_addr}: {e}"),
            }),
        }
    }

    /// Sends authenticated SIGNAL NEWNYM to Tor ControlPort
    pub fn request_newnym(port: u16) -> Result<()> {
        let addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let mut stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|_| UmbraError::TorControlError("invalid address".to_string()))?,
            Duration::from_secs(2),
        )
        .map_err(|e| {
            UmbraError::TorControlError(format!("cannot connect to ControlPort at {addr}: {e}"))
        })?;

        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|e| UmbraError::TorControlError(e.to_string()))?;

        // Locate auth cookie
        let cookie_paths = [
            "/run/tor/control.authcookie",
            "/var/run/tor/control.authcookie",
            "/var/lib/tor/control_auth_cookie",
            "/etc/tor/control_auth_cookie",
        ];

        let mut cookie_bytes = None;
        for path in &cookie_paths {
            if let Ok(mut f) = fs::File::open(path) {
                let mut bytes = Vec::new();
                if f.read_to_end(&mut bytes).is_ok() && !bytes.is_empty() {
                    cookie_bytes = Some(bytes);
                    break;
                }
            }
        }

        // Authenticate
        let auth_cmd = if let Some(cookie) = cookie_bytes {
            let hex_cookie: String = cookie.iter().map(|b| format!("{b:02x}")).collect();
            format!("AUTHENTICATE \"{hex_cookie}\"\r\n")
        } else {
            "AUTHENTICATE\r\n".to_string()
        };

        stream.write_all(auth_cmd.as_bytes()).map_err(|e| {
            UmbraError::TorControlError(format!("failed to send AUTHENTICATE: {e}"))
        })?;

        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).map_err(|e| {
            UmbraError::TorControlError(format!("failed to read auth response: {e}"))
        })?;

        if !response.starts_with("250") {
            return Err(UmbraError::TorControlError(format!(
                "authentication failed: {}",
                response.trim()
            )));
        }

        // Send SIGNAL NEWNYM
        let mut stream = reader.into_inner();
        stream
            .write_all(b"SIGNAL NEWNYM\r\n")
            .map_err(|e| UmbraError::TorControlError(format!("failed to send NEWNYM: {e}")))?;

        let mut reader = BufReader::new(stream);
        let mut nym_resp = String::new();
        reader.read_line(&mut nym_resp).map_err(|e| {
            UmbraError::TorControlError(format!("failed to read NEWNYM response: {e}"))
        })?;

        if !nym_resp.starts_with("250") {
            return Err(UmbraError::TorControlError(format!(
                "NEWNYM command failed: {}",
                nym_resp.trim()
            )));
        }

        Ok(())
    }
}
