mod common;

use std::process::{Command, Stdio};
use umbra::constants::{
    DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT, NFT_TABLE_FAMILY, NFT_TABLE_NAME, OWNERSHIP_MARKER,
};
use umbra::error::UmbraError;
use umbra::firewall::{FirewallConfig, FirewallController};

fn get_test_config() -> FirewallConfig {
    FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 122,
        tor_transport_port: DEFAULT_TOR_TRANSPORT,
        tor_dns_port: DEFAULT_TOR_DNSPORT,
        activation_id: "test_netns_act".to_string(),
    }
}

#[test]
fn test_firewall_lifecycle_isolated_netns() {
    if !common::is_in_isolated_netns() {
        // Verify host firewall has no umbra table prior to test
        let host_exists_before =
            FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap_or(false);

        let netns = common::IsolatedNetns::new("umbra_fw_life").expect("netns isolation required");
        netns.run_test("test_firewall_lifecycle_isolated_netns");

        // Verify host firewall was completely untouched by the isolated test
        let host_exists_after =
            FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap_or(false);
        assert_eq!(
            host_exists_before, host_exists_after,
            "Host firewall state was mutated by isolated netns test!"
        );
        return;
    }

    let config = get_test_config();

    // 1. Initially, table inet umbra must NOT exist in this isolated namespace
    assert!(
        !FirewallController::table_exists(&config.table_family, &config.table_name)
            .expect("query table exists"),
        "Table must not exist initially in fresh namespace"
    );

    // 2. Install the atomic firewall ruleset
    FirewallController::install(&config).expect("firewall installation must succeed");

    // 3. Verify table now exists in kernel
    assert!(
        FirewallController::table_exists(&config.table_family, &config.table_name)
            .expect("query table exists"),
        "Table must exist after installation"
    );

    // 4. Verify ownership authentication
    FirewallController::authenticate_ownership(&config.table_family, &config.table_name)
        .expect("ownership must be authenticated with marker");

    // 5. Verify live firewall verification succeeds
    FirewallController::verify_live(&config)
        .expect("live verification of chains and rules must succeed");

    // 6. Inspect raw kernel table ruleset to verify exact rules and markers
    let output = Command::new("nft")
        .args(["list", "table", &config.table_family, &config.table_name])
        .output()
        .expect("nft list table");
    assert!(output.status.success());
    let table_content = String::from_utf8_lossy(&output.stdout);

    assert!(table_content.contains("table inet umbra"));
    assert!(table_content.contains("chain output_nat"));
    assert!(table_content.contains("chain output_filter"));
    assert!(table_content.contains(OWNERSHIP_MARKER));
    assert!(table_content.contains("skuid 122 return"));
    assert!(table_content.contains("skuid 122 accept"));
    assert!(table_content.contains("redirect to :5353"));
    assert!(table_content.contains("redirect to :9040"));
    assert!(table_content.contains("reject with tcp reset"));
    assert!(table_content.contains("udp dport 443 drop"));
    assert!(table_content.contains("tcp dport 853 drop"));
    assert!(table_content.contains("udp dport 853 drop"));
    assert!(table_content.contains("meta nfproto ipv6 udp dport 53 drop"));
    assert!(table_content.contains("meta nfproto ipv6 tcp dport 53 drop"));
    assert!(table_content.contains("meta l4proto udp drop"));
    assert!(table_content.contains("ip6 daddr != ::1 drop"));

    // 7. Teardown firewall
    FirewallController::teardown(&config.table_family, &config.table_name)
        .expect("teardown must succeed");

    // 8. Verify table is completely absent after teardown
    assert!(
        !FirewallController::table_exists(&config.table_family, &config.table_name)
            .expect("query table exists"),
        "Table must be absent after teardown"
    );

    // 9. Teardown idempotency: calling teardown again when absent succeeds cleanly
    FirewallController::teardown(&config.table_family, &config.table_name)
        .expect("subsequent teardown must succeed idempotently");
}

#[test]
fn test_firewall_coexistence_with_unrelated_tables() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_fw_coex").expect("netns isolation required");
        netns.run_test("test_firewall_coexistence_with_unrelated_tables");
        return;
    }

    let config = get_test_config();
    let foreign_table = "unrelated_firewall";

    // 1. Create unrelated table and chain prior to Umbra activation
    let st = Command::new("nft")
        .args(["add", "table", "inet", foreign_table])
        .status()
        .expect("create foreign table");
    assert!(st.success());

    let st = Command::new("nft")
        .args([
            "add",
            "chain",
            "inet",
            foreign_table,
            "custom_chain",
            "{ type filter hook input priority 0; policy accept; }",
        ])
        .status()
        .expect("create foreign chain");
    assert!(st.success());

    assert!(FirewallController::table_exists("inet", foreign_table).unwrap());

    // 2. Install Umbra firewall
    FirewallController::install(&config).expect("install umbra firewall");

    // 3. Verify BOTH tables coexist in the kernel
    assert!(FirewallController::table_exists(&config.table_family, &config.table_name).unwrap());
    assert!(FirewallController::table_exists("inet", foreign_table).unwrap());

    // 4. Teardown Umbra firewall
    FirewallController::teardown(&config.table_family, &config.table_name).expect("teardown umbra");

    // 5. Verify Umbra table is gone, but unrelated table is 100% PRESERVED
    assert!(!FirewallController::table_exists(&config.table_family, &config.table_name).unwrap());
    assert!(
        FirewallController::table_exists("inet", foreign_table).unwrap(),
        "Unrelated table must NOT be destroyed by Umbra teardown"
    );

    // Verify chain is intact in the unrelated table
    let list_out = Command::new("nft")
        .args(["list", "table", "inet", foreign_table])
        .output()
        .expect("list foreign table");
    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("custom_chain"));

    // Clean up foreign table
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", foreign_table])
        .status();
}

#[test]
fn test_firewall_unauthorized_table_ownership_rejected() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_fw_auth").expect("netns isolation required");
        netns.run_test("test_firewall_unauthorized_table_ownership_rejected");
        return;
    }

    let config = get_test_config();

    // 1. Create a foreign table named `table inet umbra` WITHOUT the required ownership marker
    let st = Command::new("nft")
        .args(["add", "table", "inet", &config.table_name])
        .status()
        .expect("create rogue table");
    assert!(st.success());

    // Table exists
    assert!(FirewallController::table_exists(&config.table_family, &config.table_name).unwrap());

    // 2. Ownership authentication must FAIL
    let auth_res =
        FirewallController::authenticate_ownership(&config.table_family, &config.table_name);
    assert!(
        matches!(auth_res, Err(UmbraError::FirewallOwnershipUnknown(_))),
        "Authentication must fail when ownership marker is absent"
    );

    // 3. Teardown MUST REFUSE to delete the table because ownership cannot be proven
    let teardown_res = FirewallController::teardown(&config.table_family, &config.table_name);
    assert!(
        matches!(teardown_res, Err(UmbraError::FirewallOwnershipUnknown(_))),
        "Teardown must refuse to delete unauthenticated table"
    );

    // 4. Verify table is STILL in kernel (Umbra did not touch it)
    assert!(
        FirewallController::table_exists(&config.table_family, &config.table_name).unwrap(),
        "Foreign table must remain untouched"
    );

    // Clean up foreign table
    let _ = Command::new("nft")
        .args(["delete", "table", &config.table_family, &config.table_name])
        .status();
}

#[test]
fn test_firewall_verify_live_fails_if_chain_missing() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_fw_miss").expect("netns isolation required");
        netns.run_test("test_firewall_verify_live_fails_if_chain_missing");
        return;
    }

    let config = get_test_config();

    let marker = format!("{}:{}", OWNERSHIP_MARKER, config.activation_id);
    let partial_ruleset = format!(
        r#"table inet {table} {{
    chain output_nat {{
        type nat hook output priority dstnat; policy accept;
        comment "{marker}"
    }}
}}
"#,
        table = config.table_name,
        marker = marker
    );

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn nft");
    use std::io::Write;
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(partial_ruleset.as_bytes())
        .unwrap();
    let status = child.wait().expect("wait nft");
    assert!(status.success());

    // Ownership check passes because marker is present in comment
    assert!(
        FirewallController::authenticate_ownership(&config.table_family, &config.table_name)
            .is_ok()
    );

    // Live verification MUST fail because `output_filter` is absent
    let verify_res = FirewallController::verify_live(&config);
    assert!(
        matches!(verify_res, Err(UmbraError::FirewallVerificationFailed(_))),
        "verify_live must fail when required chain output_filter is missing"
    );

    // Teardown the table
    FirewallController::teardown(&config.table_family, &config.table_name).expect("teardown");
}

#[test]
fn test_firewall_traffic_redirection_and_blocking_in_netns() {
    if !common::is_in_isolated_netns() {
        let netns = common::IsolatedNetns::new("umbra_fw_traf").expect("netns isolation required");
        netns.run_test("test_firewall_traffic_redirection_and_blocking_in_netns");
        return;
    }

    // 1. Setup isolated dummy egress interface with default route
    let dummy_iface = "dummy_egress";
    let _ = Command::new("ip")
        .args(["link", "add", "dev", dummy_iface, "type", "dummy"])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", dummy_iface, "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", "192.0.2.2/24", "dev", dummy_iface])
        .status();
    let _ = Command::new("ip")
        .args([
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            dummy_iface,
        ])
        .status();
    let _ = Command::new("ip")
        .args([
            "neigh",
            "add",
            "192.0.2.1",
            "lladdr",
            "02:00:00:00:00:01",
            "dev",
            dummy_iface,
            "nud",
            "permanent",
        ])
        .status();

    // Configure test firewall with mock ports:
    // Process running in netns has UID 0 (root), so set tor_uid to 9999 so current process is treated as an application
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 9999,
        tor_transport_port: 19040,
        tor_dns_port: 15353,
        activation_id: "test_traffic_act".to_string(),
    };

    // Install Umbra firewall
    FirewallController::install(&config).expect("install firewall ruleset");

    // --- Test A: Application TCP Redirection to Tor TransPort ---
    let (tx_transport, rx_transport) = std::sync::mpsc::channel();
    let transport_handle = std::thread::spawn(move || {
        let listener = std::net::TcpListener::bind("127.0.0.1:19040")
            .expect("bind mock tor transport listener");
        tx_transport.send(()).expect("signal listener ready");
        let (stream, _addr) = listener.accept().expect("accept redirected connection");
        stream
    });
    rx_transport
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("mock transport listener ready");

    // Application attempts connection to an external address (192.0.2.100:80)
    let client_stream = std::net::TcpStream::connect("192.0.2.100:80")
        .expect("Client TCP connect must succeed because it is redirected to 127.0.0.1:19040");

    let server_stream = transport_handle
        .join()
        .expect("Mock TransPort on port 19040 must receive the redirected TCP connection");
    drop(client_stream);
    drop(server_stream);

    // --- Test B: UDP DNS Redirection to Tor DNSPort ---
    let dns_listener =
        std::net::UdpSocket::bind("127.0.0.1:15353").expect("bind mock tor dnsport listener");
    dns_listener
        .set_read_timeout(Some(std::time::Duration::from_secs(1)))
        .expect("set read timeout");

    let udp_client = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind client udp");
    udp_client
        .send_to(b"DNS_TEST_QUERY", "8.8.8.8:53")
        .expect("send udp dns packet");

    let mut buf = [0u8; 64];
    let (bytes_read, _peer) = dns_listener
        .recv_from(&mut buf)
        .expect("Mock DNSPort must receive redirected UDP DNS packet");
    assert_eq!(&buf[..bytes_read], b"DNS_TEST_QUERY");
    drop(dns_listener);
    drop(udp_client);

    // --- Test C: TCP DNS Leak Prevention (rejected with TCP reset, never sent to TransPort) ---
    let tcp_dns_res = std::net::TcpStream::connect_timeout(
        &"8.8.8.8:53".parse().unwrap(),
        std::time::Duration::from_millis(500),
    );
    assert!(
        tcp_dns_res.is_err(),
        "TCP DNS to port 53 must be rejected with TCP reset immediately"
    );

    // --- Test D: Loopback Communications Preserved ---
    let (tx_local, rx_local) = std::sync::mpsc::channel();
    let local_handle = std::thread::spawn(move || {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:18888").expect("bind local service listener");
        tx_local.send(()).expect("signal local ready");
        let (stream, _) = listener.accept().expect("accept local connection");
        stream
    });
    rx_local
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("local listener ready");
    let local_client = std::net::TcpStream::connect("127.0.0.1:18888")
        .expect("Local loopback communication must be preserved");
    let local_server = local_handle.join().expect("join local server");
    drop(local_client);
    drop(local_server);

    // --- Test E: QUIC (UDP/443) packet drop ---
    let quic_client = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind quic client");
    let quic_res = quic_client.send_to(b"QUIC_INITIAL_PACKET", "192.0.2.100:443");
    // Kernel output_filter drop returns EPERM (Os error 1) for locally generated UDP
    assert!(
        quic_res.is_err(),
        "QUIC packet must be dropped by output_filter"
    );
    assert_eq!(
        quic_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for dropped QUIC packet"
    );
    drop(quic_client);

    // --- Test F: DoT (TCP/853) drop (not redirected to TransPort, dropped by filter) ---
    let (tx_dot_transport, rx_dot_transport) = std::sync::mpsc::channel();
    let dot_transport_handle = std::thread::spawn(move || {
        let listener = std::net::TcpListener::bind("127.0.0.1:19040")
            .expect("bind mock tor transport listener for dot test");
        listener.set_nonblocking(true).unwrap();
        tx_dot_transport.send(()).expect("signal listener ready");
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(300) {
            if listener.accept().is_ok() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        false
    });
    rx_dot_transport
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("mock transport listener ready");

    let dot_client_res = std::net::TcpStream::connect_timeout(
        &"192.0.2.100:853".parse().unwrap(),
        std::time::Duration::from_millis(200),
    );
    assert!(
        dot_client_res.is_err(),
        "TCP DoT connection must not succeed directly"
    );

    let dot_transport_received = dot_transport_handle
        .join()
        .expect("join dot transport handle");
    assert!(
        !dot_transport_received,
        "TCP DoT (port 853) must be dropped and NEVER redirected to Tor TransPort"
    );

    // --- Test G: DoT (UDP/853) drop ---
    let dot_udp = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind dot udp");
    let dot_udp_res = dot_udp.send_to(b"DOT_UDP_QUERY", "192.0.2.100:853");
    assert!(
        dot_udp_res.is_err(),
        "DoT UDP packet must be dropped by output_filter"
    );
    assert_eq!(
        dot_udp_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for dropped DoT UDP packet"
    );
    drop(dot_udp);

    // --- Test H: IPv6 DNS Drop ---
    if let Ok(sock) = std::net::UdpSocket::bind("[::]:0") {
        let ipv6_udp_res = sock.send_to(b"IPV6_DNS_QUERY", "[::1]:53");
        assert!(
            ipv6_udp_res.is_err(),
            "IPv6 DNS query over UDP must be dropped"
        );
        assert_eq!(
            ipv6_udp_res.unwrap_err().raw_os_error(),
            Some(1),
            "Kernel must return EPERM for dropped IPv6 DNS UDP packet"
        );
    }
    let ipv6_tcp_res = std::net::TcpStream::connect_timeout(
        &"[::1]:53".parse().unwrap(),
        std::time::Duration::from_millis(100),
    );
    assert!(ipv6_tcp_res.is_err(), "IPv6 DNS over TCP must not connect");

    // --- Test I: Arbitrary Outbound UDP Drop (fail-closed) ---
    let arbitrary_udp = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind arbitrary udp");
    let arbitrary_res = arbitrary_udp.send_to(b"ARBITRARY_UDP", "192.0.2.100:12345");
    assert!(
        arbitrary_res.is_err(),
        "Arbitrary outbound UDP must be dropped (fail-closed)"
    );
    assert_eq!(
        arbitrary_res.unwrap_err().raw_os_error(),
        Some(1),
        "Kernel must return EPERM for arbitrary dropped UDP"
    );
    drop(arbitrary_udp);

    // Teardown firewall
    FirewallController::teardown(&config.table_family, &config.table_name).expect("teardown");

    // Clean up dummy interface
    let _ = Command::new("ip")
        .args(["link", "del", "dev", dummy_iface])
        .status();
}
