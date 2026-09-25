//! DNS policy definition, leak prevention, local verification, and wire-format DNS engine.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::constants::LOCAL_LOOPBACK_IPV4;
use crate::error::{Result, UmbraError};

/// DNS Header structure representing standard 12-byte RFC 1035 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

/// Parsed DNS Question entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// Simplified wire-format DNS Response containing validated header and question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
}

pub struct DnsController;

impl DnsController {
    /// Builds a standard wire-format DNS A query with Recursion Desired (RD = 1).
    pub fn build_query(domain: &str, query_id: u16) -> Result<Vec<u8>> {
        let clean_domain = domain.trim_end_matches('.');
        if clean_domain.is_empty() {
            return Err(UmbraError::DnsProtectionFailed(
                "empty domain name cannot be queried".to_string(),
            ));
        }

        if clean_domain.len() > 253 {
            return Err(UmbraError::DnsProtectionFailed(
                "domain name exceeds 253 octets limit".to_string(),
            ));
        }

        let mut packet = Vec::with_capacity(64);

        // Header (12 bytes)
        packet.extend_from_slice(&query_id.to_be_bytes()); // ID
        packet.extend_from_slice(&[0x01, 0x00]); // Flags: RD = 1, standard query
        packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

        // Question: QNAME
        for label in clean_domain.split('.') {
            if label.is_empty() {
                return Err(UmbraError::DnsProtectionFailed(
                    "domain name contains empty label".to_string(),
                ));
            }
            if label.len() > 63 {
                return Err(UmbraError::DnsProtectionFailed(
                    "domain label exceeds 63 octets limit".to_string(),
                ));
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0x00); // Root label

        // QTYPE = 1 (A), QCLASS = 1 (IN)
        packet.extend_from_slice(&[0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x01]);

        Ok(packet)
    }

    /// Parses and strictly validates a wire-format DNS response packet.
    /// Checks:
    /// - Buffer length >= 12 bytes
    /// - Matching query ID (if expected_id is provided)
    /// - QR flag is set (response, not query)
    /// - Opcode is 0 (standard query)
    /// - RCODE is valid for Tor DNSPort (0 NoError or 3 NXDomain)
    /// - Questions section is safely parsed with bounds and compression cycle checks
    pub fn parse_response(buf: &[u8], expected_id: Option<u16>) -> Result<DnsResponse> {
        if buf.len() < 12 {
            return Err(UmbraError::DnsProtectionFailed(
                "DNS response buffer too short (< 12 bytes)".to_string(),
            ));
        }

        let id = u16::from_be_bytes([buf[0], buf[1]]);
        if let Some(exp_id) = expected_id {
            if id != exp_id {
                return Err(UmbraError::DnsProtectionFailed(format!(
                    "DNS query ID mismatch: expected 0x{exp_id:04x}, received 0x{id:04x}"
                )));
            }
        }

        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let is_response = (flags & 0x8000) != 0;
        if !is_response {
            return Err(UmbraError::DnsProtectionFailed(
                "received DNS packet is a query, not a response (QR flag is 0)".to_string(),
            ));
        }

        let opcode = ((flags >> 11) & 0x0F) as u8;
        if opcode != 0 {
            return Err(UmbraError::DnsProtectionFailed(format!(
                "unexpected DNS opcode: {opcode} (expected 0 standard query)"
            )));
        }

        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        if rcode != 0 && rcode != 3 {
            return Err(UmbraError::DnsProtectionFailed(format!(
                "Tor DNS returned error RCODE {rcode} ({})",
                Self::rcode_to_str(rcode)
            )));
        }

        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let arcount = u16::from_be_bytes([buf[10], buf[11]]);

        let header = DnsHeader {
            id,
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        };

        let mut pos = 12;
        let mut questions = Vec::with_capacity((qdcount as usize).min(64));

        for _ in 0..qdcount {
            match Self::parse_name(buf, &mut pos) {
                Ok(name) => {
                    if pos + 4 <= buf.len() {
                        let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
                        let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
                        pos += 4;
                        questions.push(DnsQuestion {
                            name,
                            qtype,
                            qclass,
                        });
                    } else if !truncated {
                        return Err(UmbraError::DnsProtectionFailed(
                            "truncated DNS question section".to_string(),
                        ));
                    }
                }
                Err(e) => {
                    if !truncated {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        Ok(DnsResponse { header, questions })
    }

    /// Parses a DNS name starting at `pos`, supporting compression pointers safely.
    fn parse_name(buf: &[u8], pos: &mut usize) -> Result<String> {
        let mut labels = Vec::new();
        let mut jumped = false;
        let mut current_pos = *pos;
        let mut jumps_taken = 0;
        let max_jumps = 20;

        loop {
            if current_pos >= buf.len() {
                return Err(UmbraError::DnsProtectionFailed(
                    "DNS packet truncated while parsing name".to_string(),
                ));
            }
            let len = buf[current_pos];
            if len == 0 {
                if !jumped {
                    *pos = current_pos + 1;
                }
                break;
            }

            if (len & 0xC0) == 0xC0 {
                // Compression pointer
                if current_pos + 1 >= buf.len() {
                    return Err(UmbraError::DnsProtectionFailed(
                        "DNS compression pointer truncated".to_string(),
                    ));
                }
                let pointer_offset =
                    (((len & 0x3F) as usize) << 8) | (buf[current_pos + 1] as usize);
                if pointer_offset >= buf.len() {
                    return Err(UmbraError::DnsProtectionFailed(
                        "DNS compression pointer out of bounds".to_string(),
                    ));
                }
                if !jumped {
                    *pos = current_pos + 2;
                    jumped = true;
                }
                jumps_taken += 1;
                if jumps_taken > max_jumps {
                    return Err(UmbraError::DnsProtectionFailed(
                        "DNS compression pointer cycle detected".to_string(),
                    ));
                }
                current_pos = pointer_offset;
            } else if (len & 0xC0) == 0 {
                // Uncompressed label
                let label_len = len as usize;
                if label_len > 63 {
                    return Err(UmbraError::DnsProtectionFailed(
                        "DNS label length exceeds 63 octets".to_string(),
                    ));
                }
                current_pos += 1;
                if current_pos + label_len > buf.len() {
                    return Err(UmbraError::DnsProtectionFailed(
                        "DNS label length exceeds buffer".to_string(),
                    ));
                }
                let label_str = String::from_utf8_lossy(&buf[current_pos..current_pos + label_len]);
                labels.push(label_str.into_owned());
                current_pos += label_len;
                if !jumped {
                    *pos = current_pos;
                }
            } else {
                return Err(UmbraError::DnsProtectionFailed(format!(
                    "unsupported or reserved DNS label format 0x{len:02x}"
                )));
            }
        }

        let total_len: usize = labels.iter().map(|l| l.len() + 1).sum();
        if total_len > 255 {
            return Err(UmbraError::DnsProtectionFailed(
                "decompressed DNS name exceeds 255 octets limit".to_string(),
            ));
        }

        Ok(labels.join("."))
    }

    /// Tests DNS resolution locally against Tor DNSPort (`127.0.0.1:port`).
    /// Invariant: NEVER queries external DNS or telemetry endpoints.
    pub fn test_dns_resolution(port: u16, domain: &str, timeout: Duration) -> Result<DnsResponse> {
        let target_addr = format!("{LOCAL_LOOPBACK_IPV4}:{port}");
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| {
            UmbraError::DnsProtectionFailed(format!("failed to bind test UDP socket: {e}"))
        })?;

        socket
            .set_read_timeout(Some(timeout))
            .map_err(|e| UmbraError::DnsProtectionFailed(format!("failed to set timeout: {e}")))?;

        let parsed_target: SocketAddr = target_addr
            .parse()
            .map_err(|_| UmbraError::DnsProtectionFailed("invalid socket address".to_string()))?;

        // Generate random query ID strictly via /dev/urandom
        let mut id_bytes = [0u8; 2];
        let mut f = std::fs::File::open("/dev/urandom").map_err(|e| {
            UmbraError::DnsProtectionFailed(format!("failed to open /dev/urandom: {e}"))
        })?;
        use std::io::Read;
        f.read_exact(&mut id_bytes).map_err(|e| {
            UmbraError::DnsProtectionFailed(format!(
                "failed to read query ID from /dev/urandom: {e}"
            ))
        })?;
        let query_id = u16::from_ne_bytes(id_bytes);

        let query_packet = Self::build_query(domain, query_id)?;

        socket.send_to(&query_packet, parsed_target).map_err(|e| {
            UmbraError::DnsProtectionFailed(format!(
                "failed to send DNS query to {target_addr}: {e}"
            ))
        })?;

        let mut buf = [0u8; 4096];
        let (bytes_read, _) = socket.recv_from(&mut buf).map_err(|e| {
            UmbraError::DnsProtectionFailed(format!(
                "no response from local Tor DNSPort {target_addr}: {e}"
            ))
        })?;

        let response = Self::parse_response(&buf[..bytes_read], Some(query_id))?;

        // Verify question name matches queried domain
        let clean_domain = domain.trim_end_matches('.');
        if !response.questions.is_empty()
            && !response.questions[0]
                .name
                .eq_ignore_ascii_case(clean_domain)
        {
            return Err(UmbraError::DnsProtectionFailed(format!(
                "DNS question mismatch: expected {clean_domain}, received {}",
                response.questions[0].name
            )));
        }

        Ok(response)
    }

    /// Verifies that DNS resolution works locally via Tor DNSPort (`127.0.0.1:port`).
    pub fn verify_local_resolution(port: u16) -> Result<()> {
        Self::test_dns_resolution(port, "check.torproject.org", Duration::from_millis(2000))
            .map(|_| ())
    }

    fn rcode_to_str(rcode: u8) -> &'static str {
        match rcode {
            0 => "NoError",
            1 => "FormErr (Format Error)",
            2 => "ServFail (Server Failure)",
            3 => "NXDomain (Non-Existent Domain)",
            4 => "NotImp (Not Implemented)",
            5 => "Refused (Query Refused)",
            6 => "YXDomain (Name Exists when it should not)",
            7 => "YXRRSet (RR Set Exists when it should not)",
            8 => "NXRRSet (RR Set that should exist does not)",
            9 => "NotAuth (Server Not Authoritative for zone)",
            10 => "NotZone (Name not contained in zone)",
            _ => "Unknown Error",
        }
    }
}
