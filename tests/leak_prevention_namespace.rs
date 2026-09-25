mod common;

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME};
use umbra::dns::DnsController;
use umbra::firewall::{FirewallConfig, FirewallController};

const MOCK_TOR_UID: u32 = 9999;
const MOCK_TRANSPORT_PORT: u16 = 19040;
const MOCK_DNSPORT: u16 = 15353;
const LEAK_IFACE: &str = "leak_dummy0";

fn setup_leak_test_env() -> (FirewallConfig, String) {
    // 0. Ensure loopback interface is UP in the isolated namespace
    let _ = Command::new("ip")
        .args(["link", "set", "dev", "lo", "up"])
        .status();

    // 1. Create dummy egress interface
    let _ = Command::new("ip")
        .args(["link", "add", "dev", LEAK_IFACE, "type", "dummy"])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", LEAK_IFACE, "up"])
        .status();

    // 2. Assign IPv4 and IPv6 test subnets
    let _ = Command::new("ip")
        .args(["addr", "add", "192.0.2.10/24", "dev", LEAK_IFACE])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "2001:db8::10/64", "dev", LEAK_IFACE])
        .status();

    // 3. Set default IPv4 and IPv6 routes with permanent neighbor entries
    let _ = Command::new("ip")
        .args([
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            LEAK_IFACE,
        ])
        .status();
    let _ = Command::new("ip")
        .args([
            "neigh",
            "add",
            "192.0.2.1",
            "lladdr",
            "02:00:00:00:00:02",
            "dev",
            LEAK_IFACE,
            "nud",
            "permanent",
        ])
        .status();

    let _ = Command::new("ip")
        .args([
            "-6",
            "route",
            "add",
            "default",
            "via",
            "2001:db8::1",
            "dev",
            LEAK_IFACE,
        ])
        .status();
    let _ = Command::new("ip")
        .args([
            "-6",
            "neigh",
            "add",
            "2001:db8::1",
            "lladdr",
            "02:00:00:00:00:02",
            "dev",
            LEAK_IFACE,
            "nud",
            "permanent",
        ])
        .status();

    // 4. Populate FirewallConfig
    // Running in netns has UID 0 (root), so set tor_uid = 9999
    // so this test runner is treated as an untrusted application subject to the policy.
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: MOCK_TOR_UID,
        tor_transport_port: MOCK_TRANSPORT_PORT,
        tor_dns_port: MOCK_DNSPORT,
        activation_id: "leak_audit_test".to_string(),
    };

    (config, LEAK_IFACE.to_string())
}

fn teardown_leak_test_env(config: &FirewallConfig, iface: &str) {
    let _ = FirewallController::teardown(&config.table_family, &config.table_name);
    let _ = Command::new("ip")
        .args(["link", "del", "dev", iface])
        .status();
}

fn spawn_mock_dns_server(port: u16, max_queries: usize) -> thread::JoinHandle<()> {
    let sock = UdpSocket::bind(format!("127.0.0.1:{port}")).expect("bind mock dns server");
    sock.set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");

    thread::spawn(move || {
        for _ in 0..max_queries {
            let mut buf = [0u8; 512];
            let Ok((bytes_read, peer)) = sock.recv_from(&mut buf) else {
                break;
            };
            if bytes_read < 12 {
                continue;
            }
            let query_id = u16::from_be_bytes([buf[0], buf[1]]);
            let mut resp = Vec::new();
            resp.extend_from_slice(&query_id.to_be_bytes());
            resp.extend_from_slice(&[0x81, 0x80]); // Standard query response, NoError
            resp.extend_from_slice(&[0x00, 0x01]); // 1 question
            resp.extend_from_slice(&[0x00, 0x01]); // 1 answer
            resp.extend_from_slice(&[0x00, 0x00]);
            resp.extend_from_slice(&[0x00, 0x00]);
            resp.extend_from_slice(&buf[12..bytes_read]); // Echo question section
            resp.extend_from_slice(&[0xC0, 0x0C]); // Pointer to question name
            resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN
            resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
            resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
            resp.extend_from_slice(&[192, 0, 2, 42]); // Resolved IP: 192.0.2.42
            let _ = sock.send_to(&resp, peer);
        }
    })
}

// ---------------------------------------------------------------------------
// 1. Direct IPv4 Egress Leak Prevention Audit
// ---------------------------------------------------------------------------

#[test]
fn test_leak_direct_ipv4_egress_redirected_or_blocked() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("leak_ipv4").expect("netns required");
        netns.run_test("test_leak_direct_ipv4_egress_redirected_or_blocked");
        return;
    }

    let (config, iface) = setup_leak_test_env();
    FirewallController::install(&config).expect("install firewall");

    // Spawn mock Tor TransPort listener on 127.0.0.1:19040
    let (tx_ready, rx_ready) = mpsc::channel();
    let transport_handle = thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{MOCK_TRANSPORT_PORT}"))
            .expect("bind mock transport");
        tx_ready.send(()).unwrap();
        let (stream, _peer) = listener.accept().expect("accept redirected connection");
        stream
    });

    rx_ready.recv_timeout(Duration::from_secs(1)).unwrap();

    // A. Direct outbound TCP connection to an external clearnet destination (93.184.216.34:80)
    // Must NOT bypass to clearnet; must be transparently redirected to Tor TransPort (127.0.0.1:19040)
    let client = TcpStream::connect_timeout(
        &"93.184.216.34:80".parse().unwrap(),
        Duration::from_millis(500),
    );
    assert!(
        client.is_ok(),
        "Direct IPv4 TCP connect must succeed via transparent redirection to Tor TransPort"
    );

    let server_stream = transport_handle
        .join()
        .expect("Tor TransPort must receive the redirected external TCP connection");
    drop(client);
    drop(server_stream);

    // B. Direct outbound UDP egress attempt to external destination
    // Arbitrary UDP must be dropped fail-closed by output_filter (returning EPERM / os error 1)
    let udp_client = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    let udp_res = udp_client.send_to(b"DIRECT_UDP_EGRESS", "93.184.216.34:8080");
    assert!(
        udp_res.is_err(),
        "Direct IPv4 arbitrary UDP egress must be dropped fail-closed"
    );
    assert_eq!(
        udp_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for dropped arbitrary UDP packet"
    );

    teardown_leak_test_env(&config, &iface);
}

// ---------------------------------------------------------------------------
// 2. Direct IPv6 Egress Leak Prevention Audit (Strategy B: Total Drop)
// ---------------------------------------------------------------------------

#[test]
fn test_leak_direct_ipv6_egress_dropped_immediately() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("leak_ipv6").expect("netns required");
        netns.run_test("test_leak_direct_ipv6_egress_dropped_immediately");
        return;
    }

    let (config, iface) = setup_leak_test_env();
    FirewallController::install(&config).expect("install firewall");

    // A. IPv6 UDP to external destination
    let sock = UdpSocket::bind("[::]:0").expect("bind ipv6 udp socket in netns");
    let res = sock.send_to(b"IPV6_EGRESS_UDP", "[2001:db8::100]:1234");
    assert!(
        res.is_err(),
        "External IPv6 UDP egress must be immediately dropped"
    );
    let code = res.unwrap_err().raw_os_error();
    assert!(
        code == Some(1) || code == Some(101),
        "Kernel must return EPERM (1) or ENETUNREACH (101) for dropped IPv6 UDP: {code:?}"
    );

    // B. IPv6 UDP DNS (both external and loopback)
    let dns_res = sock.send_to(b"IPV6_DNS_QUERY", "[2001:db8::100]:53");
    assert!(
        dns_res.is_err(),
        "IPv6 UDP DNS to external port 53 must be immediately dropped"
    );
    let dns_code = dns_res.unwrap_err().raw_os_error();
    assert!(
        dns_code == Some(1) || dns_code == Some(101),
        "Kernel must return EPERM or ENETUNREACH for dropped IPv6 external DNS: {dns_code:?}"
    );

    let loopback_dns_res = sock.send_to(b"IPV6_DNS_QUERY", "[::1]:53");
    assert!(
        loopback_dns_res.is_err(),
        "IPv6 UDP DNS to loopback port 53 must be dropped with EPERM"
    );
    assert_eq!(
        loopback_dns_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for dropped IPv6 loopback DNS"
    );

    // C. IPv6 TCP to external destination ([2001:db8::100]:80)
    let tcp_res = TcpStream::connect_timeout(
        &"[2001:db8::100]:80".parse().unwrap(),
        Duration::from_millis(200),
    );
    assert!(
        tcp_res.is_err(),
        "External IPv6 TCP connect must fail immediately without bypassing"
    );

    // D. IPv6 TCP DNS to external resolver ([2001:db8::100]:53 and [::1]:53)
    let tcp_dns_res = TcpStream::connect_timeout(
        &"[2001:db8::100]:53".parse().unwrap(),
        Duration::from_millis(200),
    );
    assert!(
        tcp_dns_res.is_err(),
        "External IPv6 TCP DNS connect must fail immediately"
    );

    let tcp_loopback_dns_res =
        TcpStream::connect_timeout(&"[::1]:53".parse().unwrap(), Duration::from_millis(200));
    assert!(
        tcp_loopback_dns_res.is_err(),
        "Loopback IPv6 TCP DNS connect must fail immediately"
    );

    teardown_leak_test_env(&config, &iface);
}

// ---------------------------------------------------------------------------
// 3. Direct Clearnet DNS Leak Prevention Audit (UDP 53 and TCP 53)
// ---------------------------------------------------------------------------

#[test]
fn test_leak_clearnet_dns_udp_and_tcp() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("leak_dns").expect("netns required");
        netns.run_test("test_leak_clearnet_dns_udp_and_tcp");
        return;
    }

    let (config, iface) = setup_leak_test_env();
    FirewallController::install(&config).expect("install firewall");

    // Spawn mock Tor DNSPort on 127.0.0.1:15353
    let mock_dns = spawn_mock_dns_server(MOCK_DNSPORT, 2);

    // Spawn mock Tor TransPort on 127.0.0.1:19040 to verify TCP DNS NEVER touches TransPort
    let (tx_ready, rx_ready) = mpsc::channel();
    let (tx_stop, rx_stop) = mpsc::channel();
    let transport_handle = thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{MOCK_TRANSPORT_PORT}"))
            .expect("bind mock transport");
        listener.set_nonblocking(true).unwrap();
        tx_ready.send(()).unwrap();

        let mut received = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(500) {
            if rx_stop.try_recv().is_ok() {
                break;
            }
            if listener.accept().is_ok() {
                received = true;
            }
            thread::sleep(Duration::from_millis(15));
        }
        received
    });
    rx_ready.recv_timeout(Duration::from_secs(1)).unwrap();

    let client_sock = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    client_sock
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");

    // A. Direct UDP DNS queries to public resolvers (8.8.8.8:53 and 1.1.1.1:53)
    // Must be transparently intercepted and redirected to Tor DNSPort (127.0.0.1:15353)
    for (idx, target) in ["8.8.8.8:53", "1.1.1.1:53"].iter().enumerate() {
        let q_id = 0x8800 + idx as u16;
        let query = DnsController::build_query("check.torproject.org", q_id).unwrap();
        client_sock
            .send_to(&query, target)
            .expect("send udp dns query");

        let mut resp_buf = [0u8; 512];
        let (bytes_read, _) = client_sock
            .recv_from(&mut resp_buf)
            .expect("receive redirected DNS response");

        let parsed = DnsController::parse_response(&resp_buf[..bytes_read], Some(q_id))
            .expect("parse DNS response");
        assert_eq!(parsed.header.id, q_id);
        assert_eq!(
            parsed.header.rcode, 0,
            "DNS query to {target} was successfully answered by Tor DNSPort via NAT redirection"
        );
        assert!(parsed.header.is_response);
    }

    // B. Direct TCP DNS queries to public resolvers (8.8.8.8:53 and 1.1.1.1:53)
    // Per Section 20, TCP port 53 must be rejected with TCP RST immediately,
    // and must NEVER be redirected to Tor TransPort
    for target in ["8.8.8.8:53", "1.1.1.1:53"] {
        let tcp_res =
            TcpStream::connect_timeout(&target.parse().unwrap(), Duration::from_millis(500));
        assert!(
            tcp_res.is_err(),
            "Direct TCP DNS to {target} must be rejected immediately"
        );
        let err = tcp_res.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "Direct TCP DNS must receive ConnectionRefused (TCP RST)"
        );
    }

    let _ = tx_stop.send(());
    let transport_received_tcp_dns = transport_handle.join().unwrap();
    assert!(
        !transport_received_tcp_dns,
        "TCP DNS must NEVER be redirected to Tor TransPort"
    );

    mock_dns.join().unwrap();
    teardown_leak_test_env(&config, &iface);
}

// ---------------------------------------------------------------------------
// 4. Loopback Stub Resolver DNS Leak Prevention Audit (127.0.0.53 & 127.0.0.1)
// ---------------------------------------------------------------------------

#[test]
fn test_leak_loopback_stub_resolver_dns() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("leak_stub").expect("netns required");
        netns.run_test("test_leak_loopback_stub_resolver_dns");
        return;
    }

    let (config, iface) = setup_leak_test_env();
    FirewallController::install(&config).expect("install firewall");

    // Spawn mock Tor DNSPort on 127.0.0.1:15353
    let mock_dns = spawn_mock_dns_server(MOCK_DNSPORT, 2);

    let client_sock = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    client_sock
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");

    // A. Queries to systemd-resolved stub (127.0.0.53:53) and local resolver (127.0.0.1:53)
    // Must be redirected to Tor DNSPort (127.0.0.1:15353) before loopback bypass rules
    for (idx, target) in ["127.0.0.53:53", "127.0.0.1:53"].iter().enumerate() {
        let q_id = 0x9900 + idx as u16;
        let query = DnsController::build_query("check.torproject.org", q_id).unwrap();
        client_sock
            .send_to(&query, target)
            .expect("send udp dns query to loopback stub");

        let mut resp_buf = [0u8; 512];
        let (bytes_read, _) = client_sock
            .recv_from(&mut resp_buf)
            .expect("receive redirected DNS response");

        let parsed = DnsController::parse_response(&resp_buf[..bytes_read], Some(q_id))
            .expect("parse DNS response");
        assert_eq!(parsed.header.id, q_id);
        assert_eq!(
            parsed.header.rcode, 0,
            "Loopback stub DNS query to {target} was safely redirected to Tor DNSPort"
        );
        assert!(parsed.header.is_response);
    }

    // B. Loopback TCP DNS queries (127.0.0.53:53 and 127.0.0.1:53)
    // Must be rejected with TCP RST
    for target in ["127.0.0.53:53", "127.0.0.1:53"] {
        let tcp_res =
            TcpStream::connect_timeout(&target.parse().unwrap(), Duration::from_millis(500));
        assert!(
            tcp_res.is_err(),
            "Loopback TCP DNS to {target} must be rejected with RST"
        );
        assert_eq!(
            tcp_res.unwrap_err().kind(),
            std::io::ErrorKind::ConnectionRefused
        );
    }

    mock_dns.join().unwrap();
    teardown_leak_test_env(&config, &iface);
}

// ---------------------------------------------------------------------------
// 5. QUIC Bypass (UDP 443) Leak Prevention Audit
// ---------------------------------------------------------------------------

#[test]
fn test_leak_quic_bypass_udp443_dropped() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("leak_quic").expect("netns required");
        netns.run_test("test_leak_quic_bypass_udp443_dropped");
        return;
    }

    let (config, iface) = setup_leak_test_env();
    FirewallController::install(&config).expect("install firewall");

    let quic_client = UdpSocket::bind("0.0.0.0:0").expect("bind quic client");

    // Outbound QUIC packets to external destinations must be dropped immediately by output_filter
    for target in ["93.184.216.34:443", "1.1.1.1:443", "192.0.2.100:443"] {
        let res = quic_client.send_to(b"QUIC_INITIAL_CLIENT_HELLO", target);
        assert!(
            res.is_err(),
            "Outbound QUIC (UDP 443) to {target} must be dropped by output_filter"
        );
        assert_eq!(
            res.unwrap_err().raw_os_error(),
            Some(1),
            "Kernel must return EPERM for dropped QUIC packet"
        );
    }

    teardown_leak_test_env(&config, &iface);
}

// ---------------------------------------------------------------------------
// 6. DoT Bypass (TCP/UDP 853) Leak Prevention Audit
// ---------------------------------------------------------------------------

#[test]
fn test_leak_dot_bypass_tcp_and_udp853_dropped() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("leak_dot").expect("netns required");
        netns.run_test("test_leak_dot_bypass_tcp_and_udp853_dropped");
        return;
    }

    let (config, iface) = setup_leak_test_env();
    FirewallController::install(&config).expect("install firewall");

    // Spawn mock Tor TransPort listener to verify TCP DoT is NEVER redirected to TransPort
    let (tx_ready, rx_ready) = mpsc::channel();
    let (tx_stop, rx_stop) = mpsc::channel();
    let transport_handle = thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{MOCK_TRANSPORT_PORT}"))
            .expect("bind mock transport");
        listener.set_nonblocking(true).unwrap();
        tx_ready.send(()).unwrap();

        let mut received = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(400) {
            if rx_stop.try_recv().is_ok() {
                break;
            }
            if listener.accept().is_ok() {
                received = true;
            }
            thread::sleep(Duration::from_millis(15));
        }
        received
    });
    rx_ready.recv_timeout(Duration::from_secs(1)).unwrap();

    // A. TCP DoT (port 853) to external destination (93.184.216.34:853)
    // Must be dropped by output_filter (neither connect directly nor redirect to TransPort)
    let tcp_dot_res = TcpStream::connect_timeout(
        &"93.184.216.34:853".parse().unwrap(),
        Duration::from_millis(200),
    );
    assert!(
        tcp_dot_res.is_err(),
        "TCP DoT (port 853) connection must not succeed directly"
    );

    let _ = tx_stop.send(());
    let transport_received_dot = transport_handle.join().unwrap();
    assert!(
        !transport_received_dot,
        "TCP DoT (port 853) must NEVER be redirected to Tor TransPort"
    );

    // B. UDP DoT (port 853 - DNS-over-QUIC) to external destination
    // Must be dropped immediately by output_filter
    let dot_udp = UdpSocket::bind("0.0.0.0:0").expect("bind dot udp");
    let udp_dot_res = dot_udp.send_to(b"DOT_UDP_QUERY", "93.184.216.34:853");
    assert!(
        udp_dot_res.is_err(),
        "UDP DoT (port 853) packet must be dropped"
    );
    assert_eq!(
        udp_dot_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for dropped UDP DoT packet"
    );

    teardown_leak_test_env(&config, &iface);
}

// ---------------------------------------------------------------------------
// 7. Tor Failure Injection (Tor Crash / Unreachable while Firewall Active)
// ---------------------------------------------------------------------------

#[test]
fn test_leak_tor_failure_injection_fail_closed() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("leak_tor_fail").expect("netns required");
        netns.run_test("test_leak_tor_failure_injection_fail_closed");
        return;
    }

    let (config, iface) = setup_leak_test_env();
    FirewallController::install(&config).expect("install firewall");

    // Phase 1: Tor is initially running and accepting connections
    let listener = TcpListener::bind(format!("127.0.0.1:{MOCK_TRANSPORT_PORT}"))
        .expect("bind initial mock transport");
    let (tx_ready, rx_ready) = mpsc::channel();
    let initial_handle = thread::spawn(move || {
        tx_ready.send(()).unwrap();
        let (stream, _) = listener.accept().expect("accept initial connection");
        stream
    });
    rx_ready.recv_timeout(Duration::from_secs(1)).unwrap();

    let client = TcpStream::connect_timeout(
        &"93.184.216.34:80".parse().unwrap(),
        Duration::from_millis(500),
    );
    assert!(
        client.is_ok(),
        "Traffic is initially routed through Tor TransPort"
    );
    drop(client);
    let s = initial_handle.join().unwrap();
    drop(s);

    // Phase 2: INJECT TOR FAILURE (Simulate Tor daemon crash / SIGKILL)
    // The Tor TransPort and DNSPort sockets are completely closed.
    // The firewall ruleset 'table inet umbra' remains active in the kernel.

    // A. Outbound application TCP attempts to connect to clearnet
    // Because TransPort is dead (127.0.0.1:19040 closed), connection must be REFUSED.
    // CRITICALLY: It must NEVER bypass the dead Tor proxy to connect to 93.184.216.34:80!
    let failed_tcp = TcpStream::connect_timeout(
        &"93.184.216.34:80".parse().unwrap(),
        Duration::from_millis(500),
    );
    assert!(
        failed_tcp.is_err(),
        "When Tor crashes, TCP must fail closed (ECONNREFUSED) and NEVER fall back to direct clearnet"
    );
    assert_eq!(
        failed_tcp.unwrap_err().kind(),
        std::io::ErrorKind::ConnectionRefused,
        "Redirected connection to closed TransPort returns ConnectionRefused"
    );

    // B. Outbound DNS attempts when Tor DNSPort is dead
    // Because DNSPort is dead (127.0.0.1:15353 closed), UDP DNS queries must timeout.
    // CRITICALLY: They must NEVER fall back to direct physical DNS!
    let dns_client = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    dns_client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("timeout");
    let q = DnsController::build_query("check.torproject.org", 0xfa11).unwrap();
    let _ = dns_client.send_to(&q, "8.8.8.8:53");

    let mut buf = [0u8; 512];
    let recv_res = dns_client.recv_from(&mut buf);
    assert!(
        recv_res.is_err(),
        "When Tor DNSPort is dead, DNS queries must fail closed (timeout) and NEVER reach physical DNS"
    );

    // C. Non-Tor UDP egress remains dropped with EPERM
    let arbitrary_udp = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    let udp_res = arbitrary_udp.send_to(b"FAIL_CLOSED_CHECK", "93.184.216.34:12345");
    assert!(
        udp_res.is_err(),
        "Arbitrary UDP must remain dropped during Tor failure"
    );
    assert_eq!(
        udp_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel returns EPERM for dropped UDP during Tor failure"
    );

    // D. IPv6 egress remains completely blocked
    let sock6 = UdpSocket::bind("[::]:0").expect("bind ipv6 udp socket in failure injection");
    let v6_res = sock6.send_to(b"IPV6_FAIL_CLOSED", "[2001:db8::100]:80");
    assert!(v6_res.is_err(), "IPv6 must fail closed during Tor failure");
    let code = v6_res.unwrap_err().raw_os_error();
    assert!(
        code == Some(1) || code == Some(101),
        "Kernel returns EPERM (1) or ENETUNREACH (101) for IPv6 during Tor failure: {code:?}"
    );

    // Phase 3: TOR RECOVERY
    // When Tor is restored, traffic safely resumes without leaving fail-closed boundary
    let restored_listener = TcpListener::bind(format!("127.0.0.1:{MOCK_TRANSPORT_PORT}"))
        .expect("bind restored mock transport");
    let (tx_restored, rx_restored) = mpsc::channel();
    let restored_handle = thread::spawn(move || {
        tx_restored.send(()).unwrap();
        let (stream, _) = restored_listener
            .accept()
            .expect("accept restored connection");
        stream
    });
    rx_restored.recv_timeout(Duration::from_secs(1)).unwrap();

    let restored_client = TcpStream::connect_timeout(
        &"93.184.216.34:80".parse().unwrap(),
        Duration::from_millis(500),
    );
    assert!(
        restored_client.is_ok(),
        "Traffic resumes safely through Tor once TransPort is back online"
    );
    drop(restored_client);
    let s2 = restored_handle.join().unwrap();
    drop(s2);

    teardown_leak_test_env(&config, &iface);
}
