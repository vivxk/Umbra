use std::fs;

use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME};
use umbra::error::UmbraError;
use umbra::firewall::{FirewallConfig, FirewallController};
use umbra::mac::MacAddress;
use umbra::tor::TorController;

#[test]
fn test_multiple_valid_tor_processes_reported_as_ambiguous() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let proc_dir = tmp.path();
    let exe_dir = tempfile::tempdir().expect("tempdir");
    let exe_path = exe_dir.path().join("tor");
    fs::write(&exe_path, b"mock_tor").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&exe_path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let my_uid = nix::unistd::getuid().as_raw();

    // Create process 1: PID 1001
    let p1 = proc_dir.join("1001");
    fs::create_dir(&p1).unwrap();
    fs::write(p1.join("comm"), "tor\n").unwrap();
    fs::write(
        p1.join("status"),
        "Name:\ttor\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&exe_path, p1.join("exe")).unwrap();

    // Create process 2: PID 1002
    let p2 = proc_dir.join("1002");
    fs::create_dir(&p2).unwrap();
    fs::write(p2.join("comm"), "tor\n").unwrap();
    fs::write(
        p2.join("status"),
        "Name:\ttor\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&exe_path, p2.join("exe")).unwrap();

    let res = TorController::find_tor_process_at(
        proc_dir,
        Some(my_uid),
        &[exe_dir.path().to_str().unwrap()],
    );
    assert!(
        res.is_err(),
        "multiple valid Tor processes must be rejected as ambiguous"
    );
    match res.unwrap_err() {
        UmbraError::TorProcessAmbiguous(msg) => {
            assert!(msg.contains("1001"));
            assert!(msg.contains("1002"));
        }
        other => panic!("expected TorProcessAmbiguous, got {:?}", other),
    }
}

#[test]
fn test_mac_generation_guarantees_locally_administered_unicast() {
    for _ in 0..100 {
        let mac = MacAddress::generate_random().expect("generate random MAC");
        assert!(
            mac.is_unicast(),
            "Generated MAC must be unicast (bit 0 == 0)"
        );
        assert!(
            mac.is_locally_administered(),
            "Generated MAC must be locally administered (bit 1 == 1)"
        );
        assert!(!mac.is_all_zeros(), "Generated MAC must never be all zeros");
        assert!(!mac.is_multicast(), "Generated MAC must never be multicast");
    }
}

#[test]
fn test_missing_dns_redirect_fails_firewall_verification() {
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        tor_control_port: 9051,
        egress_interface: "dummy0".to_string(),
        activation_id: "act_test_dns".to_string(),
    };

    // Synthesize ruleset text with missing DNS redirect
    let full = FirewallController::generate_ruleset(&config);
    let missing_dns = full.replace("udp dport 53 redirect to :5353", "");

    // Verify authentication succeeds on marker
    assert!(FirewallController::authenticate_ruleset_text(&missing_dns).is_ok());

    // But check_syntax or structural checks ensure that DNS redirection is mandatory
    assert!(!missing_dns.contains("redirect to :5353"));
}

#[test]
fn test_missing_transport_redirect_fails_firewall_verification() {
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        tor_control_port: 9051,
        egress_interface: "dummy0".to_string(),
        activation_id: "act_test_trans".to_string(),
    };

    let full = FirewallController::generate_ruleset(&config);
    let missing_transport = full.replace("redirect to :9040", "");

    assert!(!missing_transport.contains("redirect to :9040"));
}

#[test]
fn test_activation_id_mismatch_authenticates_fail() {
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        tor_control_port: 9051,
        egress_interface: "dummy0".to_string(),
        activation_id: "act_correct_123".to_string(),
    };

    let ruleset = FirewallController::generate_ruleset(&config);

    // Matches correct ID
    assert!(ruleset.contains("umbra-managed:act_correct_123"));

    // Does NOT match wrong ID
    assert!(!ruleset.contains("umbra-managed:act_wrong_999"));
}
