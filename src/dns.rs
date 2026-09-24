//! DNS policy definition, leak prevention, local verification, and wire-format DNS engine.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
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

/// Parsed DNS Resource Record entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
    pub ip_addr: Option<Ipv4Addr>,
}

/// EDNS(0) OPT pseudo-record metadata (RFC 6891).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOpt {
    pub udp_payload_size: u16,
    pub extended_rcode: u8,
    pub version: u8,
    pub dnssec_ok: bool,
}

/// Complete parsed wire-format DNS Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub edns: Option<EdnsOpt>,
}

/// Structured diagnostics for `/etc/resolv.conf`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvConfDiagnostics {
    pub path: String,
    pub nameservers: Vec<String>,
    pub options: Vec<String>,
    pub search_domains: Vec<String>,
    pub loopback_only: bool,
    pub public_or_remote_nameservers: Vec<String>,
    pub warnings: Vec<String>,
}

pub struct DnsController;

impl DnsController {
    /// Builds a standard wire-format DNS A query with Recursion Desired (RD = 1).
    pub fn build_query(domain: &str, query_id: u16) -> Result<Vec<u8>> {
        Self::build_query_internal(domain, query_id, None)
    }

    /// Builds a wire-format DNS A query with EDNS(0) OPT pseudo-RR in additional section.
    pub fn build_query_with_edns(
        domain: &str,
        query_id: u16,
        edns_payload_size: u16,
    ) -> Result<Vec<u8>> {
        Self::build_query_internal(domain, query_id, Some(edns_payload_size))
    }

    fn build_query_internal(
        domain: &str,
        query_id: u16,
        edns_payload: Option<u16>,
    ) -> Result<Vec<u8>> {
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

        if edns_payload.is_some() {
            packet.extend_from_slice(&[0x00, 0x01]); // ARCOUNT = 1
        } else {
            packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
        }

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

        // EDNS(0) OPT pseudo-record if requested
        if let Some(payload_size) = edns_payload {
            packet.push(0x00); // Root name
            packet.extend_from_slice(&[0x00, 0x29]); // Type 41 (OPT)
            packet.extend_from_slice(&payload_size.to_be_bytes()); // UDP payload size (Class)
            packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Extended RCODE & flags
            packet.extend_from_slice(&[0x00, 0x00]); // RDLENGTH = 0
        }

        Ok(packet)
    }

    /// Parses and strictly validates a wire-format DNS response packet.
    /// Checks:
    /// - Buffer length >= 12 bytes
    /// - Matching query ID (if expected_id is provided)
    /// - QR flag is set (response, not query)
    /// - Opcode is 0 (standard query)
    /// - RCODE is valid for Tor DNSPort (0 NoError or 3 NXDomain)
    /// - Truncation and EDNS(0) presence
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
        let mut questions = Vec::with_capacity(qdcount as usize);

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

        let mut answers = Vec::with_capacity(ancount as usize);
        for _ in 0..ancount {
            match Self::parse_record(buf, &mut pos) {
                Ok(rec) => answers.push(rec),
                Err(e) => {
                    if !truncated {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        let mut authorities = Vec::with_capacity(nscount as usize);
        for _ in 0..nscount {
            match Self::parse_record(buf, &mut pos) {
                Ok(rec) => authorities.push(rec),
                Err(e) => {
                    if !truncated {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        let mut additionals = Vec::with_capacity(arcount as usize);
        let mut edns = None;

        for _ in 0..arcount {
            match Self::parse_record(buf, &mut pos) {
                Ok(rec) => {
                    if rec.rtype == 41 {
                        // OPT pseudo-record
                        let udp_payload_size = rec.rclass;
                        let extended_rcode = (rec.ttl >> 24) as u8;
                        let version = ((rec.ttl >> 16) & 0xFF) as u8;
                        let dnssec_ok = (rec.ttl & 0x8000) != 0;
                        edns = Some(EdnsOpt {
                            udp_payload_size,
                            extended_rcode,
                            version,
                            dnssec_ok,
                        });
                    }
                    additionals.push(rec);
                }
                Err(e) => {
                    if !truncated {
                        return Err(e);
                    }
                    break;
                }
            }
        }

        Ok(DnsResponse {
            header,
            questions,
            answers,
            authorities,
            additionals,
            edns,
        })
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
            } else {
                let label_len = len as usize;
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
            }
        }

        Ok(labels.join("."))
    }

    /// Parses a single Resource Record from `pos`.
    fn parse_record(buf: &[u8], pos: &mut usize) -> Result<DnsRecord> {
        let name = Self::parse_name(buf, pos)?;
        if *pos + 10 > buf.len() {
            return Err(UmbraError::DnsProtectionFailed(
                "truncated DNS resource record header".to_string(),
            ));
        }

        let rtype = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]);
        let rclass = u16::from_be_bytes([buf[*pos + 2], buf[*pos + 3]]);
        let ttl = u32::from_be_bytes([buf[*pos + 4], buf[*pos + 5], buf[*pos + 6], buf[*pos + 7]]);
        let rdlength = u16::from_be_bytes([buf[*pos + 8], buf[*pos + 9]]) as usize;
        *pos += 10;

        if *pos + rdlength > buf.len() {
            return Err(UmbraError::DnsProtectionFailed(
                "truncated DNS resource record RDATA".to_string(),
            ));
        }

        let rdata = buf[*pos..*pos + rdlength].to_vec();
        *pos += rdlength;

        let ip_addr = if rtype == 1 && rdlength == 4 {
            Some(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
        } else {
            None
        };

        Ok(DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
            ip_addr,
        })
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

        // Generate query ID based on time / address
        let query_id = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0xABCD)
            & 0xFFFF) as u16;

        let query_packet = Self::build_query(domain, query_id)?;

        socket.send_to(&query_packet, parsed_target).map_err(|e| {
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

        Self::parse_response(&buf[..bytes_read], Some(query_id))
    }

    /// Verifies that DNS resolution works locally via Tor DNSPort (`127.0.0.1:port`).
    pub fn verify_local_resolution(port: u16) -> Result<()> {
        Self::test_dns_resolution(port, "check.torproject.org", Duration::from_millis(2000))
            .map(|_| ())
    }

    /// Safely parses `/etc/resolv.conf` content without mutating system files.
    pub fn parse_resolv_conf(content: &str) -> ResolvConfDiagnostics {
        let mut nameservers = Vec::new();
        let mut options = Vec::new();
        let mut search_domains = Vec::new();
        let mut public_or_remote_nameservers = Vec::new();
        let mut warnings = Vec::new();

        for line in content.lines() {
            // Strip comments (# and ;)
            let line_no_comment = line.split('#').next().unwrap_or("");
            let line_clean = line_no_comment.split(';').next().unwrap_or("").trim();

            if line_clean.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line_clean.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "nameserver" => {
                    for &ns in &parts[1..] {
                        let ns_str = ns.to_string();
                        nameservers.push(ns_str.clone());

                        if !Self::is_loopback_address(&ns_str) {
                            public_or_remote_nameservers.push(ns_str.clone());
                            warnings.push(format!(
                                "Configured nameserver '{ns_str}' is non-loopback. While Umbra firewall intercepts outbound port 53, standard applications relying on unintercepted DNS or systemd-resolved could experience timeouts or leakage risks if firewall is down. Consider setting nameserver 127.0.0.1."
                            ));
                        }
                    }
                }
                "options" => {
                    for &opt in &parts[1..] {
                        options.push(opt.to_string());
                    }
                }
                "search" => {
                    for &domain in &parts[1..] {
                        search_domains.push(domain.to_string());
                    }
                }
                "domain" if parts.len() >= 2 => {
                    search_domains.push(parts[1].to_string());
                }
                _ => {}
            }
        }

        if nameservers.is_empty() {
            warnings.push("No nameservers found in resolv.conf".to_string());
        }

        let loopback_only = !nameservers.is_empty() && public_or_remote_nameservers.is_empty();

        ResolvConfDiagnostics {
            path: "/etc/resolv.conf".to_string(),
            nameservers,
            options,
            search_domains,
            loopback_only,
            public_or_remote_nameservers,
            warnings,
        }
    }

    /// Inspects the host `/etc/resolv.conf` safely (read-only).
    pub fn inspect_resolv_conf() -> Result<ResolvConfDiagnostics> {
        Self::inspect_resolv_conf_path("/etc/resolv.conf")
    }

    /// Inspects a given resolv.conf file safely.
    pub fn inspect_resolv_conf_path<P: AsRef<Path>>(path: P) -> Result<ResolvConfDiagnostics> {
        let p = path.as_ref();
        let content = fs::read_to_string(p).map_err(|e| {
            UmbraError::DnsProtectionFailed(format!("failed to read {}: {e}", p.display()))
        })?;

        let mut diag = Self::parse_resolv_conf(&content);
        diag.path = p.display().to_string();
        Ok(diag)
    }

    /// Reads configured nameservers from `/etc/resolv.conf` for backward compatibility.
    pub fn read_configured_nameservers() -> Vec<String> {
        Self::inspect_resolv_conf()
            .map(|d| d.nameservers)
            .unwrap_or_default()
    }

    /// Checks if a string represents an IPv4 or IPv6 loopback address.
    pub fn is_loopback_address(addr_str: &str) -> bool {
        if let Ok(ip) = addr_str.parse::<IpAddr>() {
            ip.is_loopback()
        } else {
            addr_str.starts_with("127.") || addr_str == "::1"
        }
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
