use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;
use umbra::dns::DnsController;
use umbra::error::UmbraError;

#[test]
fn test_read_configured_nameservers() {
    let servers = DnsController::read_configured_nameservers();
    // In Linux environments with /etc/resolv.conf, this should not panic
    println!("Discovered nameservers: {servers:?}");
}

#[test]
fn test_build_query_valid() {
    let query =
        DnsController::build_query("check.torproject.org", 0x1234).expect("build standard query");

    // Header checks
    assert_eq!(&query[0..2], &[0x12, 0x34]); // ID
    assert_eq!(&query[2..4], &[0x01, 0x00]); // Flags: RD = 1
    assert_eq!(&query[4..6], &[0x00, 0x01]); // QDCOUNT = 1
    assert_eq!(&query[6..8], &[0x00, 0x00]); // ANCOUNT = 0
    assert_eq!(&query[8..10], &[0x00, 0x00]); // NSCOUNT = 0
    assert_eq!(&query[10..12], &[0x00, 0x00]); // ARCOUNT = 0

    // Question section
    // 5 "check" 10 "torproject" 3 "org" 0
    let mut expected_qname = vec![5];
    expected_qname.extend_from_slice(b"check");
    expected_qname.push(10);
    expected_qname.extend_from_slice(b"torproject");
    expected_qname.push(3);
    expected_qname.extend_from_slice(b"org");
    expected_qname.push(0);

    let qname_len = expected_qname.len();
    assert_eq!(&query[12..12 + qname_len], &expected_qname[..]);

    let offset = 12 + qname_len;
    assert_eq!(&query[offset..offset + 2], &[0x00, 0x01]); // QTYPE = A
    assert_eq!(&query[offset + 2..offset + 4], &[0x00, 0x01]); // QCLASS = IN
}

#[test]
fn test_build_query_trailing_dot_handled() {
    let q1 = DnsController::build_query("example.com", 0x4321).unwrap();
    let q2 = DnsController::build_query("example.com.", 0x4321).unwrap();
    assert_eq!(q1, q2);
}

#[test]
fn test_build_query_with_edns() {
    let query = DnsController::build_query_with_edns("example.com", 0x5566, 4096)
        .expect("build EDNS query");

    // ARCOUNT should be 1
    assert_eq!(&query[10..12], &[0x00, 0x01]);

    // Check OPT record at the end
    // Root name: 0x00
    // Type: 41 (0x0029)
    // Class: 4096 (0x1000)
    let len = query.len();
    assert_eq!(
        &query[len - 11..len],
        &[
            0x00, // Name root
            0x00, 0x29, // Type OPT
            0x10, 0x00, // Class (payload size 4096)
            0x00, 0x00, 0x00, 0x00, // Ext RCODE & flags
            0x00, 0x00, // RDLENGTH = 0
        ]
    );
}

#[test]
fn test_build_query_invalid_domains_rejected() {
    // Empty domain
    assert!(matches!(
        DnsController::build_query("", 0x1111),
        Err(UmbraError::DnsProtectionFailed(_))
    ));

    // Empty label (consecutive dots)
    assert!(matches!(
        DnsController::build_query("foo..bar", 0x1111),
        Err(UmbraError::DnsProtectionFailed(_))
    ));

    // Label exceeding 63 bytes
    let long_label = "a".repeat(64);
    let domain = format!("{long_label}.com");
    assert!(matches!(
        DnsController::build_query(&domain, 0x1111),
        Err(UmbraError::DnsProtectionFailed(_))
    ));

    // Total length exceeding 253 bytes
    let label = "abcdefghij"; // 10 chars
    let domain = (0..26).map(|_| label).collect::<Vec<_>>().join(".");
    assert!(domain.len() > 253);
    assert!(matches!(
        DnsController::build_query(&domain, 0x1111),
        Err(UmbraError::DnsProtectionFailed(_))
    ));
}

#[test]
fn test_parse_response_valid_a_record() {
    // Build a synthetic valid response packet for check.torproject.org -> 116.202.120.181
    let mut packet = Vec::new();
    // Header
    packet.extend_from_slice(&[0xAB, 0xCD]); // ID = 0xABCD
    packet.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, Opcode=0, RD=1, RA=1, RCODE=0
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // Question: check.torproject.org A IN
    packet.push(5);
    packet.extend_from_slice(b"check");
    packet.push(10);
    packet.extend_from_slice(b"torproject");
    packet.push(3);
    packet.extend_from_slice(b"org");
    packet.push(0);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN

    // Answer: Name pointer to question at offset 12 (0xC00C), Type A, Class IN, TTL 300, RDLENGTH 4, 116.202.120.181
    packet.extend_from_slice(&[0xC0, 0x0C]); // Pointer to check.torproject.org
    packet.extend_from_slice(&[0x00, 0x01]); // Type A
    packet.extend_from_slice(&[0x00, 0x01]); // Class IN
    packet.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // TTL 300
    packet.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
    packet.extend_from_slice(&[116, 202, 120, 181]); // IP

    let res = DnsController::parse_response(&packet, Some(0xABCD)).expect("parse response");

    assert_eq!(res.header.id, 0xABCD);
    assert!(res.header.is_response);
    assert_eq!(res.header.opcode, 0);
    assert_eq!(res.header.rcode, 0);
    assert_eq!(res.header.qdcount, 1);
    assert_eq!(res.header.ancount, 1);
    assert_eq!(res.questions.len(), 1);
    assert_eq!(res.questions[0].name, "check.torproject.org");
    assert_eq!(res.answers.len(), 1);
    assert_eq!(res.answers[0].name, "check.torproject.org");
    assert_eq!(
        res.answers[0].ip_addr,
        Some(Ipv4Addr::new(116, 202, 120, 181))
    );
}

#[test]
fn test_parse_response_nxdomain_valid() {
    // Tor returns NXDomain (RCODE 3) for nonexistent domains, which is a valid response
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x99, 0x88]); // ID
    packet.extend_from_slice(&[0x81, 0x83]); // QR=1, RD=1, RA=1, RCODE=3 (NXDomain)
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
    packet.push(7);
    packet.extend_from_slice(b"invalid");
    packet.push(0);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let res = DnsController::parse_response(&packet, Some(0x9988)).expect("parse NXDomain");
    assert_eq!(res.header.rcode, 3);
    assert_eq!(res.answers.len(), 0);
}

#[test]
fn test_parse_response_short_buffer_rejected() {
    let short_packet = [0x01, 0x02, 0x81, 0x80]; // only 4 bytes
    let err = DnsController::parse_response(&short_packet, None).unwrap_err();
    assert!(err.to_string().contains("too short"));
}

#[test]
fn test_parse_response_id_mismatch_rejected() {
    let packet = [
        0x11, 0x11, // ID 0x1111
        0x81, 0x80, // Response
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let err = DnsController::parse_response(&packet, Some(0x2222)).unwrap_err();
    assert!(err.to_string().contains("ID mismatch"));
}

#[test]
fn test_parse_response_not_a_response_rejected() {
    let packet = [
        0x12, 0x34, 0x01, 0x00, // QR = 0 (Query)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let err = DnsController::parse_response(&packet, Some(0x1234)).unwrap_err();
    assert!(err.to_string().contains("QR flag is 0"));
}

#[test]
fn test_parse_response_unexpected_opcode_rejected() {
    let packet = [
        0x12, 0x34, 0x88, 0x00, // QR=1, Opcode=1 (Inverse Query)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let err = DnsController::parse_response(&packet, Some(0x1234)).unwrap_err();
    assert!(err.to_string().contains("unexpected DNS opcode"));
}

#[test]
fn test_parse_response_server_failure_rcode_rejected() {
    let packet = [
        0x12, 0x34, 0x81, 0x82, // QR=1, RCODE=2 (ServFail)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let err = DnsController::parse_response(&packet, Some(0x1234)).unwrap_err();
    assert!(err.to_string().contains("ServFail"));
}

#[test]
fn test_parse_response_refused_rcode_rejected() {
    let packet = [
        0x12, 0x34, 0x81, 0x85, // QR=1, RCODE=5 (Refused)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let err = DnsController::parse_response(&packet, Some(0x1234)).unwrap_err();
    assert!(err.to_string().contains("Refused"));
}

#[test]
fn test_parse_response_truncated_handling() {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0xAA, 0xBB]);
    packet.extend_from_slice(&[0x83, 0x80]); // QR=1, TC=1 (Truncated)
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    packet.extend_from_slice(&[0x00, 0x05]); // Claims 5 answers, but packet cuts off
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.push(4);
    packet.extend_from_slice(b"test");
    packet.push(0);
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    let res = DnsController::parse_response(&packet, Some(0xAABB)).expect("parse truncated");
    assert!(res.header.truncated);
    assert_eq!(res.questions.len(), 1);
    assert_eq!(res.answers.len(), 0);
}

#[test]
fn test_parse_response_with_edns_opt_rr() {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x55, 0x66]);
    packet.extend_from_slice(&[0x81, 0x80]); // QR=1, RCODE=0
    packet.extend_from_slice(&[0x00, 0x00]); // QDCOUNT=0
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    packet.extend_from_slice(&[0x00, 0x01]); // ARCOUNT=1 (OPT RR)

    // OPT RR: Name=0, Type=41, UDP size=1232 (Class), TTL=0x00000000, RDLENGTH=0
    packet.push(0x00); // Root name
    packet.extend_from_slice(&[0x00, 0x29]); // Type 41
    packet.extend_from_slice(&[0x04, 0xD0]); // UDP payload 1232
    packet.extend_from_slice(&[0x00, 0x00, 0x80, 0x00]); // Extended RCODE 0, Version 0, DO bit set
    packet.extend_from_slice(&[0x00, 0x00]); // RDLENGTH 0

    let res = DnsController::parse_response(&packet, Some(0x5566)).expect("parse EDNS");
    assert!(res.edns.is_some());
    let edns = res.edns.unwrap();
    assert_eq!(edns.udp_payload_size, 1232);
    assert_eq!(edns.extended_rcode, 0);
    assert!(edns.dnssec_ok);
}

#[test]
fn test_parse_response_compression_cycle_prevented() {
    let mut packet = Vec::new();
    packet.extend_from_slice(&[0x77, 0x88]);
    packet.extend_from_slice(&[0x81, 0x80]);
    packet.extend_from_slice(&[0x00, 0x01]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet.extend_from_slice(&[0x00, 0x00]);

    // Create a pointer loop at offset 12: 0xC00C points to offset 12
    packet.extend_from_slice(&[0xC0, 0x0C]);

    let err = DnsController::parse_response(&packet, Some(0x7788)).unwrap_err();
    assert!(err.to_string().contains("cycle detected"));
}

#[test]
fn test_resolv_conf_parser_loopback_only() {
    let content = r#"
# Standard Linux resolver config
nameserver 127.0.0.1
nameserver 127.0.0.53 # systemd-resolved
nameserver ::1
options edns0 trust-ad timeout:2
search localdomain lan
domain localdomain
"#;
    let diag = DnsController::parse_resolv_conf(content);

    assert_eq!(diag.nameservers, vec!["127.0.0.1", "127.0.0.53", "::1"]);
    assert!(diag.loopback_only);
    assert!(diag.public_or_remote_nameservers.is_empty());
    assert!(diag.warnings.is_empty());
    assert_eq!(diag.options, vec!["edns0", "trust-ad", "timeout:2"]);
    assert_eq!(
        diag.search_domains,
        vec!["localdomain", "lan", "localdomain"]
    );
}

#[test]
fn test_resolv_conf_parser_public_nameserver_warning() {
    let content = r#"
; Semicolon comment
nameserver 8.8.8.8
nameserver 1.1.1.1
nameserver 127.0.0.1
options timeout:1
"#;
    let diag = DnsController::parse_resolv_conf(content);

    assert_eq!(diag.nameservers, vec!["8.8.8.8", "1.1.1.1", "127.0.0.1"]);
    assert!(!diag.loopback_only);
    assert_eq!(
        diag.public_or_remote_nameservers,
        vec!["8.8.8.8", "1.1.1.1"]
    );
    assert_eq!(diag.warnings.len(), 2);
    assert!(diag.warnings[0].contains("8.8.8.8"));
    assert!(diag.warnings[1].contains("1.1.1.1"));
}

#[test]
fn test_resolv_conf_parser_empty_content() {
    let content = "   \n# Only comments\n; another comment\n  \n";
    let diag = DnsController::parse_resolv_conf(content);

    assert!(diag.nameservers.is_empty());
    assert!(!diag.loopback_only);
    assert_eq!(diag.warnings.len(), 1);
    assert!(diag.warnings[0].contains("No nameservers found"));
}

#[test]
fn test_mock_local_dnsport_resolution() {
    // Spin up an ephemeral local UDP server mimicking Tor DNSPort
    let server_sock = UdpSocket::bind("127.0.0.1:0").expect("bind mock server");
    let server_port = server_sock.local_addr().unwrap().port();

    let server_handle = std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (bytes_read, peer) = server_sock.recv_from(&mut buf).expect("mock recv");

        // Parse query ID from client
        let query_id = u16::from_be_bytes([buf[0], buf[1]]);

        // Construct mock response
        let mut resp = Vec::new();
        resp.extend_from_slice(&query_id.to_be_bytes()); // ID matches client
        resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RCODE=0
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&[0x00, 0x00]);

        // Copy question section from query
        let q_end = bytes_read;
        resp.extend_from_slice(&buf[12..q_end]);

        // Add answer: pointer to question name at offset 12, Type A, Class IN, TTL 60, IP 127.0.0.1
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[127, 0, 0, 1]);

        server_sock.send_to(&resp, peer).expect("mock send");
    });

    let dns_resp =
        DnsController::test_dns_resolution(server_port, "localhost.local", Duration::from_secs(1))
            .expect("test DNS resolution against mock");

    assert_eq!(dns_resp.header.rcode, 0);
    assert_eq!(dns_resp.answers.len(), 1);
    assert_eq!(
        dns_resp.answers[0].ip_addr,
        Some(Ipv4Addr::new(127, 0, 0, 1))
    );

    server_handle.join().unwrap();
}

#[test]
fn test_mock_local_dnsport_timeout() {
    // Choose an unused port without a listener
    let unused_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let unused_port = unused_sock.local_addr().unwrap().port();
    drop(unused_sock);

    let res =
        DnsController::test_dns_resolution(unused_port, "test.domain", Duration::from_millis(50));
    assert!(res.is_err());
    assert!(matches!(res, Err(UmbraError::DnsProtectionFailed(_))));
}
