//! DNS policy definition, leak prevention, and local verification.

use std::fs;
use std::net::UdpSocket;
use std::time::Duration;

use crate::constants::LOCAL_LOOPBACK_IPV4;
use crate::error::{Result, UmbraError};

pub struct DnsController;

impl DnsController {
    /// Tests that DNS resolution works locally via Tor DNSPort
    pub fn verify_local_resolution(port: u16) -> Result<()> {
        let target_addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| {
            UmbraError::DnsProtectionFailed(format!("failed to bind test socket: {e}"))
        })?;

        socket
            .set_read_timeout(Some(Duration::from_millis(1500)))
            .map_err(|e| UmbraError::DnsProtectionFailed(format!("failed to set timeout: {e}")))?;

        // Query for "check.torproject.org"
        let query_packet = [
            0xAB, 0xCD, // ID
            0x01, 0x00, // Recursion desired
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, b'c', b'h', b'e', b'c', b'k', 0x09, b't',
            b'o', b'r', b'p', b'r', b'o', b'j', b'e', b'c', b't', 0x03, b'o', b'r', b'g', 0x00,
            0x00, 0x01, // Type A
            0x00, 0x01, // Class IN
        ];

        socket.send_to(&query_packet, &target_addr).map_err(|e| {
            UmbraError::DnsProtectionFailed(format!(
                "failed to send DNS query to {target_addr}: {e}"
            ))
        })?;

        let mut buf = [0u8; 512];
        let (bytes_read, _) = socket.recv_from(&mut buf).map_err(|e| {
            UmbraError::DnsProtectionFailed(format!(
                "no response from local Tor DNSPort {target_addr}: {e}"
            ))
        })?;

        if bytes_read < 12 {
            return Err(UmbraError::DnsProtectionFailed(
                "malformed short DNS reply from Tor".to_string(),
            ));
        }

        // Response code in byte 3 (lower 4 bits)
        let rcode = buf[3] & 0x0F;
        if rcode != 0 && rcode != 3 {
            // 0 = NoError, 3 = NXDomain
            return Err(UmbraError::DnsProtectionFailed(format!(
                "Tor DNS returned error RCODE {rcode}"
            )));
        }

        Ok(())
    }

    /// Reads nameservers configured in /etc/resolv.conf for informational reporting
    pub fn read_configured_nameservers() -> Vec<String> {
        let mut servers = Vec::new();
        if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("nameserver") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        servers.push(parts[1].to_string());
                    }
                }
            }
        }
        servers
    }
}
