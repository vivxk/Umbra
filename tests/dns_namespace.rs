mod common;

use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME};
use umbra::dns::DnsController;
use umbra::firewall::{FirewallConfig, FirewallController};

const TEST_TOR_UID: u32 = 9999;
const TEST_TOR_TRANSPORT: u16 = 19040;
const TEST_TOR_DNSPORT: u16 = 15353;
const TEST_TOR_CONTROLPORT: u16 = 19051;
const DUMMY_IFACE: &str = "dns_dummy0";

fn setup_netns_environment() -> (FirewallConfig, String) {
    let _ = Command::new("ip")
        .args(["link", "add", "dev", DUMMY_IFACE, "type", "dummy"])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", DUMMY_IFACE, "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "192.0.2.10/24", "dev", DUMMY_IFACE])
        .status();
    let _ = Command::new("ip")
        .args([
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            DUMMY_IFACE,
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
            DUMMY_IFACE,
            "nud",
            "permanent",
        ])
        .status();

    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: TEST_TOR_UID,
        tor_transport_port: TEST_TOR_TRANSPORT,
        tor_dns_port: TEST_TOR_DNSPORT,
        tor_control_port: TEST_TOR_CONTROLPORT,
        egress_interface: DUMMY_IFACE.to_string(),
        activation_id: "dns_netns_test".to_string(),
    };

    (config, DUMMY_IFACE.to_string())
}

fn teardown_netns_environment(config: &FirewallConfig, iface: &str) {
    let _ = FirewallController::teardown(&config.table_family, &config.table_name);
    let _ = Command::new("ip")
        .args(["link", "del", "dev", iface])
        .status();
}

#[test]
fn test_dns_netns_udp53_redirection_to_tor_dnsport() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_dns_red").expect("netns isolation required");
        netns.run_test("test_dns_netns_udp53_redirection_to_tor_dnsport");
        return;
    }

    let (config, iface) = setup_netns_environment();
    FirewallController::install(&config).expect("install firewall in netns");

    // Start mock Tor DNSPort listener on 127.0.0.1:15353
    let dns_sock = UdpSocket::bind(format!("127.0.0.1:{TEST_TOR_DNSPORT}"))
        .expect("bind mock tor dns listener");
    dns_sock
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set read timeout");

    let server_handle = thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (bytes_read, peer) = dns_sock.recv_from(&mut buf).expect("recv dns query");
        let query_id = u16::from_be_bytes([buf[0], buf[1]]);

        // Build valid response for the query
        let mut resp = Vec::new();
        resp.extend_from_slice(&query_id.to_be_bytes());
        resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RCODE=0
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&buf[12..bytes_read]); // Question echo
        resp.extend_from_slice(&[0xC0, 0x0C]); // Pointer to name
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Type A, Class IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
        resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        resp.extend_from_slice(&[192, 0, 2, 42]); // Resolved IP: 192.0.2.42

        dns_sock.send_to(&resp, peer).expect("send dns reply");
    });

    // Client sends query to external public DNS: 8.8.8.8:53
    let client_sock = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    client_sock
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("client read timeout");

    let query_bytes = DnsController::build_query("check.torproject.org", 0x7777).unwrap();
    client_sock
        .send_to(&query_bytes, "8.8.8.8:53")
        .expect("send query to 8.8.8.8:53");

    let mut resp_buf = [0u8; 512];
    let (n, _) = client_sock
        .recv_from(&mut resp_buf)
        .expect("client recv response redirected from DNSPort");

    let parsed_resp =
        DnsController::parse_response(&resp_buf[..n], Some(0x7777)).expect("parse response");
    assert_eq!(parsed_resp.header.id, 0x7777);
    assert_eq!(parsed_resp.header.rcode, 0);
    assert_eq!(parsed_resp.answers.len(), 1);
    assert_eq!(
        parsed_resp.answers[0].ip_addr,
        Some(Ipv4Addr::new(192, 0, 2, 42))
    );

    server_handle.join().unwrap();
    teardown_netns_environment(&config, &iface);
}

#[test]
fn test_dns_netns_tcp53_rejected_with_rst() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_dns_rst").expect("netns isolation required");
        netns.run_test("test_dns_netns_tcp53_rejected_with_rst");
        return;
    }

    let (config, iface) = setup_netns_environment();
    FirewallController::install(&config).expect("install firewall in netns");

    // Start mock TransPort on 127.0.0.1:19040 to verify TCP/53 is NEVER sent to TransPort
    let (tx, rx) = mpsc::channel();
    let transport_handle = thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{TEST_TOR_TRANSPORT}"))
            .expect("bind mock transport");
        listener.set_nonblocking(true).unwrap();
        tx.send(()).unwrap();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(300) {
            if listener.accept().is_ok() {
                return true;
            }
            thread::sleep(Duration::from_millis(15));
        }
        false
    });
    rx.recv_timeout(Duration::from_secs(1)).unwrap();

    // Application attempts TCP connection to port 53 (e.g., DNS TCP fallback)
    let tcp_res =
        TcpStream::connect_timeout(&"8.8.8.8:53".parse().unwrap(), Duration::from_millis(500));

    // Must fail immediately due to TCP reset
    assert!(
        tcp_res.is_err(),
        "TCP DNS to port 53 must be rejected immediately with TCP reset"
    );

    let err = tcp_res.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused,
        "TCP DNS must receive ConnectionRefused (TCP RST), not timeout"
    );

    let transport_received = transport_handle.join().unwrap();
    assert!(
        !transport_received,
        "TCP DNS (port 53) must NEVER be redirected to Tor TransPort"
    );

    teardown_netns_environment(&config, &iface);
}

#[test]
fn test_dns_netns_quic_udp443_dropped() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_quic_drp").expect("netns isolation required");
        netns.run_test("test_dns_netns_quic_udp443_dropped");
        return;
    }

    let (config, iface) = setup_netns_environment();
    FirewallController::install(&config).expect("install firewall in netns");

    let quic_client = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    let res = quic_client.send_to(b"QUIC_PACKET_PAYLOAD", "192.0.2.100:443");

    // Kernel nftables output_filter drops packet, returning EPERM (Os error 1)
    assert!(
        res.is_err(),
        "Outbound QUIC (UDP/443) must be dropped by packet filter"
    );
    assert_eq!(
        res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for dropped QUIC packet"
    );

    teardown_netns_environment(&config, &iface);
}

#[test]
fn test_dns_netns_dot_tcp_and_udp_853_dropped() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_dot_drp").expect("netns isolation required");
        netns.run_test("test_dns_netns_dot_tcp_and_udp_853_dropped");
        return;
    }

    let (config, iface) = setup_netns_environment();
    FirewallController::install(&config).expect("install firewall in netns");

    // Mock TransPort to verify TCP 853 is not redirected
    let (tx, rx) = mpsc::channel();
    let transport_handle = thread::spawn(move || {
        let listener = TcpListener::bind(format!("127.0.0.1:{TEST_TOR_TRANSPORT}"))
            .expect("bind mock transport");
        listener.set_nonblocking(true).unwrap();
        tx.send(()).unwrap();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_millis(300) {
            if listener.accept().is_ok() {
                return true;
            }
            thread::sleep(Duration::from_millis(15));
        }
        false
    });
    rx.recv_timeout(Duration::from_secs(1)).unwrap();

    // 1. TCP 853 (DoT over TCP)
    let tcp_dot_res = TcpStream::connect_timeout(
        &"192.0.2.100:853".parse().unwrap(),
        Duration::from_millis(200),
    );
    assert!(
        tcp_dot_res.is_err(),
        "DoT over TCP (port 853) must be dropped by output filter"
    );
    let transport_saw_dot = transport_handle.join().unwrap();
    assert!(
        !transport_saw_dot,
        "DoT over TCP must NEVER be redirected to Tor TransPort"
    );

    // 2. UDP 853 (DoT / DoQ over UDP)
    let udp_dot = UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    let udp_dot_res = udp_dot.send_to(b"DOT_UDP_PACKET", "192.0.2.100:853");
    assert!(
        udp_dot_res.is_err(),
        "DoT over UDP (port 853) must be dropped by output filter"
    );
    assert_eq!(
        udp_dot_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for dropped DoT UDP packet"
    );

    teardown_netns_environment(&config, &iface);
}

#[test]
fn test_dns_netns_ipv6_dns_dropped() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_ipv6_drp").expect("netns isolation required");
        netns.run_test("test_dns_netns_ipv6_dns_dropped");
        return;
    }

    let (config, iface) = setup_netns_environment();
    FirewallController::install(&config).expect("install firewall in netns");

    // 1. IPv6 UDP/53
    if let Ok(sock) = UdpSocket::bind("[::]:0") {
        let res = sock.send_to(b"IPV6_DNS", "[::1]:53");
        assert!(res.is_err(), "IPv6 UDP DNS query must be dropped");
        assert_eq!(
            res.unwrap_err().raw_os_error(),
            Some(1),
            "Kernel must return EPERM for dropped IPv6 UDP DNS"
        );
    }

    // 2. IPv6 TCP/53
    let tcp_res =
        TcpStream::connect_timeout(&"[::1]:53".parse().unwrap(), Duration::from_millis(100));
    assert!(
        tcp_res.is_err(),
        "IPv6 TCP DNS query must be dropped or rejected"
    );

    teardown_netns_environment(&config, &iface);
}

#[test]
fn test_dns_netns_local_dns_engine_resolution() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_dns_eng").expect("netns isolation required");
        netns.run_test("test_dns_netns_local_dns_engine_resolution");
        return;
    }

    let (config, iface) = setup_netns_environment();
    FirewallController::install(&config).expect("install firewall in netns");

    // Start mock Tor DNSPort listener on 127.0.0.1:15353
    let dns_sock = UdpSocket::bind(format!("127.0.0.1:{TEST_TOR_DNSPORT}"))
        .expect("bind mock tor dns listener");
    dns_sock
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("set timeout");

    let server_handle = thread::spawn(move || {
        let mut buf = [0u8; 512];
        let (bytes_read, peer) = dns_sock.recv_from(&mut buf).expect("mock recv");
        let query_id = u16::from_be_bytes([buf[0], buf[1]]);

        let mut resp = Vec::new();
        resp.extend_from_slice(&query_id.to_be_bytes());
        resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RCODE=0
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&buf[12..bytes_read]);
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        resp.extend_from_slice(&[0x00, 0x04]);
        resp.extend_from_slice(&[127, 0, 0, 1]);

        dns_sock.send_to(&resp, peer).expect("mock send");
    });

    // Run DnsController local resolution engine against local DNSPort in netns
    let resp = DnsController::test_dns_resolution(
        TEST_TOR_DNSPORT,
        "check.torproject.org",
        Duration::from_secs(1),
    )
    .expect("DnsController test_dns_resolution must succeed against mock Tor DNSPort");

    assert_eq!(resp.header.rcode, 0);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(resp.answers[0].ip_addr, Some(Ipv4Addr::new(127, 0, 0, 1)));

    server_handle.join().unwrap();
    teardown_netns_environment(&config, &iface);
}
