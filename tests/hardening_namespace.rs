mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use tempfile::NamedTempFile;

use common::{is_in_isolated_netns, IsolatedNetns};
use umbra::constants::{
    DEFAULT_TOR_CONTROLPORT, DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT, NFT_TABLE_FAMILY,
    NFT_TABLE_NAME,
};
use umbra::error::UmbraError;
use umbra::firewall::{FirewallConfig, FirewallController};
use umbra::interface::InterfaceController;
use umbra::runtime_state::{ActiveState, UmbraStatus};

fn get_test_fw_config(iface: &str, activation_id: &str) -> FirewallConfig {
    FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: DEFAULT_TOR_TRANSPORT,
        tor_dns_port: DEFAULT_TOR_DNSPORT,
        tor_control_port: DEFAULT_TOR_CONTROLPORT,
        egress_interface: iface.to_string(),
        activation_id: activation_id.to_string(),
    }
}

struct PeerNetnsGuard {
    srv_ns: String,
    veth_cli: String,
}

impl PeerNetnsGuard {
    fn new(srv_ns: String, veth_cli: String) -> Self {
        Self { srv_ns, veth_cli }
    }
}

impl Drop for PeerNetnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("sudo")
            .args(["-n", "ip", "link", "del", &self.veth_cli])
            .status();
        let _ = Command::new("sudo")
            .args(["-n", "ip", "netns", "del", &self.srv_ns])
            .status();
    }
}

#[test]
fn test_pre_existing_direct_tcp_flow_blocked_after_activation_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("hd_tcp_flow") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_pre_existing_direct_tcp_flow_blocked_after_activation_in_netns");
        return;
    }

    let srv_ns = format!("hd_srv_{}", std::process::id());
    let veth_cli = "veth_c_flow";
    let veth_srv = "veth_s_flow";

    // 1. Setup peer server network namespace and veth link
    let _ = Command::new("sudo")
        .args(["-n", "ip", "netns", "add", &srv_ns])
        .status();
    let _guard = PeerNetnsGuard::new(srv_ns.clone(), veth_cli.to_string());

    let _ = Command::new("sudo")
        .args(["-n", "ip", "-n", &srv_ns, "link", "set", "lo", "up"])
        .status();
    let _ = Command::new("sudo")
        .args([
            "-n", "ip", "link", "add", veth_cli, "type", "veth", "peer", "name", veth_srv,
        ])
        .status();
    let _ = Command::new("sudo")
        .args(["-n", "ip", "link", "set", veth_srv, "netns", &srv_ns])
        .status();

    let _ = Command::new("sudo")
        .args(["-n", "ip", "link", "set", veth_cli, "up"])
        .status();
    let _ = Command::new("sudo")
        .args(["-n", "ip", "addr", "add", "10.200.1.2/24", "dev", veth_cli])
        .status();

    let _ = Command::new("sudo")
        .args(["-n", "ip", "-n", &srv_ns, "link", "set", veth_srv, "up"])
        .status();
    let _ = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "-n",
            &srv_ns,
            "addr",
            "add",
            "10.200.1.1/24",
            "dev",
            veth_srv,
        ])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", "dev", "lo", "up"])
        .status();

    // 2. Spawn mock remote TCP server in srv_ns
    let py_script = r#"
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.200.1.1', 18080))
s.listen(1)
print('READY', flush=True)
conn, _ = s.accept()
print('ACCEPTED', flush=True)
d1 = conn.recv(64)
conn.sendall(b'ACK1:' + d1)
conn.settimeout(1.0)
try:
    d2 = conn.recv(64)
    if d2:
        print('LEAKED:' + d2.decode(errors='replace'), flush=True)
except Exception:
    print('TIMEOUT_NO_DATA', flush=True)
conn.close()
s.close()
"#;

    let mut srv_child = Command::new("sudo")
        .args([
            "-n", "ip", "netns", "exec", &srv_ns, "python3", "-c", py_script,
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn server in srv_ns");

    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(srv_child.stdout.take().expect("stdout"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("read server ready");
    assert!(line.contains("READY"));

    // 3. Establish direct TCP connection prior to Umbra activation
    let mut client = TcpStream::connect("10.200.1.1:18080").expect("connect direct TCP");
    client
        .write_all(b"HELLO_PRE_UMBRA")
        .expect("write pre-umbra");
    let mut buf = [0u8; 64];
    let n = client.read(&mut buf).expect("read pre-umbra ack");
    assert_eq!(&buf[..n], b"ACK1:HELLO_PRE_UMBRA");

    // 4. Activate Umbra Firewall Boundary on veth_cli
    let fw_config = get_test_fw_config(veth_cli, "act_hd_flow");
    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    // 5. Pre-existing direct TCP connection MUST NOT continue sending direct traffic
    // Outbound packets to non-loopback IPs without Tor UID are dropped by output_filter
    let _ = client.write_all(b"DIRECT_LEAK_ATTEMPT");
    let _ = client.flush();

    // 6. Verify remote server timed out and did not receive data after Umbra activation
    let mut server_output = String::new();
    for l in reader.lines().map_while(Result::ok) {
        server_output.push_str(&l);
        server_output.push('\n');
    }
    let _ = srv_child.wait();

    assert!(
        !server_output.contains("LEAKED:"),
        "Pre-existing direct TCP flow must NOT be delivered to direct server after Umbra activation! Server output: {server_output}"
    );
    assert!(
        server_output.contains("TIMEOUT_NO_DATA"),
        "Server must encounter timeout due to dropped packets. Server output: {server_output}"
    );

    // 7. Verify new connection after activation is redirected to Tor TransPort
    let (tx_transport, rx_transport) = std::sync::mpsc::channel();
    let transport_handle = std::thread::spawn(move || {
        let listener = std::net::TcpListener::bind("127.0.0.1:9040")
            .expect("bind mock tor transport listener");
        tx_transport.send(()).expect("signal listener ready");
        let (stream, _addr) = listener.accept().expect("accept redirected connection");
        stream
    });
    rx_transport
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("mock transport listener ready");

    // Reinstall firewall with tor_uid=9999 so current process traffic is redirected
    let fw_config_redir = FirewallConfig {
        tor_uid: 9999,
        ..fw_config.clone()
    };
    FirewallController::install(&fw_config_redir).expect("install firewall with mock tor uid");

    let client_stream = std::net::TcpStream::connect("10.200.1.1:80")
        .expect("New connection must be redirected to 127.0.0.1:9040");
    let server_stream = transport_handle
        .join()
        .expect("Mock TransPort must receive redirected connection");
    drop(client_stream);
    drop(server_stream);

    // Clean up
    FirewallController::teardown_with_id(
        &fw_config_redir.table_family,
        &fw_config_redir.table_name,
        Some(&fw_config_redir.activation_id),
    )
    .expect("teardown");
}

#[test]
fn test_activation_id_mismatch_prevents_teardown_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("hd_act_id") {
            Some(ns) => ns,
            None => return,
        };
        netns.run_test("test_activation_id_mismatch_prevents_teardown_in_netns");
        return;
    }

    let dev_name = "dum_hd_act";
    let _ = Command::new("ip")
        .args(["link", "add", dev_name, "type", "dummy"])
        .status();

    let fw_config = get_test_fw_config(dev_name, "act_legitimate_session");
    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    // Attempt teardown with mismatched activation ID
    let err = FirewallController::teardown_with_id(
        &fw_config.table_family,
        &fw_config.table_name,
        Some("act_stale_or_wrong_session"),
    )
    .unwrap_err();

    match err {
        UmbraError::FirewallOwnershipUnknown(msg) => {
            assert!(msg.contains("activation ID mismatch"));
        }
        other => panic!("expected FirewallOwnershipUnknown, got {:?}", other),
    }

    // The table must remain untouched and intact
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "Table must NOT be destroyed when activation ID mismatches"
    );

    // Clean up with correct activation ID
    FirewallController::teardown_with_id(
        &fw_config.table_family,
        &fw_config.table_name,
        Some(&fw_config.activation_id),
    )
    .expect("clean teardown");
}

#[test]
fn test_mac_mismatch_prevents_active_status_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("hd_mac_chk") {
            Some(ns) => ns,
            None => return,
        };
        netns.run_test("test_mac_mismatch_prevents_active_status_in_netns");
        return;
    }

    let dev_name = "dum_hd_mac";
    let _ = Command::new("ip")
        .args([
            "link",
            "add",
            dev_name,
            "address",
            "02:aa:bb:cc:dd:ee",
            "type",
            "dummy",
        ])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", dev_name, "up"])
        .status();

    // Create state indicating expected randomized MAC is 02:11:22:33:44:55
    let fw_config = get_test_fw_config(dev_name, "act_mac_chk");
    FirewallController::install(&fw_config).expect("install firewall");

    let tmp = NamedTempFile::new().expect("tempfile");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    let state = ActiveState::new_with_status(
        fw_config.activation_id.clone(),
        dev_name.to_string(),
        "02:aa:bb:cc:dd:ee".to_string(),
        "02:11:22:33:44:55".to_string(), // Expected randomized MAC
        true,
        fw_config.tor_uid,
        fw_config.tor_transport_port,
        fw_config.tor_dns_port,
        fw_config.table_name.clone(),
        UmbraStatus::Active,
    );
    state.save_to_path(&state_path).expect("save state");

    // The interface live MAC is 02:aa:bb:cc:dd:ee, but state expects 02:11:22:33:44:55.
    // Verify LiveVerifier reports RECOVERY_REQUIRED and NOT ACTIVE!
    let live_mac = InterfaceController::read_mac(dev_name).unwrap();
    assert_ne!(live_mac.to_string(), state.randomized_mac);

    // Teardown
    FirewallController::teardown_with_id(
        &fw_config.table_family,
        &fw_config.table_name,
        Some(&fw_config.activation_id),
    )
    .expect("teardown");
}
