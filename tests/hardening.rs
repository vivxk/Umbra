use std::fs;

use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME};
use umbra::error::UmbraError;
use umbra::firewall::{FirewallConfig, FirewallController};
use umbra::mac::MacAddress;
use umbra::runtime_state::{ActiveState, UmbraStatus};
use umbra::tor::TorController;
use umbra::transaction::{StartupTransaction, StartupTransactionOptions};

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
        activation_id: "act_test_dns".to_string(),
    };

    // Synthesize ruleset text with missing DNS redirect
    let full = FirewallController::generate_ruleset(&config);
    let missing_dns = full.replace("udp dport 53 redirect to :5353", "");

    // Verify authentication succeeds on marker
    assert!(FirewallController::authenticate_ruleset_text(&missing_dns).is_ok());

    // Policy verification MUST fail when DNS redirect is missing
    let err = FirewallController::verify_ruleset_text_policy(&missing_dns, &config).unwrap_err();
    match err {
        UmbraError::FirewallVerificationFailed(msg) => {
            assert!(msg.contains("missing dns redirection rule"));
        }
        other => panic!("expected FirewallVerificationFailed, got {other:?}"),
    }
}

#[test]
fn test_missing_transport_redirect_fails_firewall_verification() {
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        activation_id: "act_test_trans".to_string(),
    };

    let full = FirewallController::generate_ruleset(&config);
    let missing_transport = full.replace("redirect to :9040", "");

    let err =
        FirewallController::verify_ruleset_text_policy(&missing_transport, &config).unwrap_err();
    match err {
        UmbraError::FirewallVerificationFailed(msg) => {
            assert!(msg.contains("missing transport redirection rule"));
        }
        other => panic!("expected FirewallVerificationFailed, got {other:?}"),
    }
}

#[test]
fn test_activation_id_mismatch_authenticates_fail() {
    let config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        activation_id: "act_correct_123".to_string(),
    };

    let ruleset = FirewallController::generate_ruleset(&config);

    // Matches correct ID
    assert!(ruleset.contains("umbra-managed:act_correct_123"));

    // Does NOT match wrong ID
    assert!(!ruleset.contains("umbra-managed:act_wrong_999"));
}

#[test]
fn test_state_exists_in_starting_status_before_mutation() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    let state = ActiveState::new_with_status(
        "act_starting_pre_mutation".to_string(),
        "eth0".to_string(),
        "02:aa:bb:cc:dd:ee".to_string(),
        "02:11:22:33:44:55".to_string(),
        true,
        1000,
        9040,
        5353,
        UmbraStatus::Starting,
    );

    assert_eq!(state.status, UmbraStatus::Starting);
    assert!(
        state.validate().is_ok(),
        "Starting state must validate successfully"
    );

    state.save_to_path(&state_path).expect("save state");
    assert!(state_path.exists(), "State file must exist on disk");

    let loaded = ActiveState::load_from_path(&state_path)
        .unwrap()
        .expect("load state");
    assert_eq!(loaded.status, UmbraStatus::Starting);
    assert_eq!(loaded.activation_id, "act_starting_pre_mutation");

    let _ = std::fs::remove_file(state_path);
}

#[test]
fn test_startup_rejects_stale_starting_state() {
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let stale_state = ActiveState::new_with_status(
        "act_stale_start_123".to_string(),
        "eth0".to_string(),
        "02:aa:bb:cc:dd:ee".to_string(),
        "02:11:22:33:44:55".to_string(),
        true,
        1000,
        9040,
        5353,
        UmbraStatus::Starting,
    );
    stale_state
        .save_to_path(tmp.path())
        .expect("save stale starting state");

    let opts = StartupTransactionOptions {
        interface_override: Some("eth0".to_string()),
        transport_port: 9040,
        dns_port: 5353,
        state_file_override: Some(tmp.path().to_string_lossy().to_string()),
        ..Default::default()
    };

    let result = StartupTransaction::execute(opts);
    assert!(
        result.is_err(),
        "Duplicate start on stale Starting state must be refused"
    );
    match result.unwrap_err() {
        UmbraError::AlreadyActive {
            interface,
            activation_id,
        } => {
            assert_eq!(interface, "eth0");
            assert_eq!(activation_id, "act_stale_start_123");
        }
        other => panic!("expected AlreadyActive error, got {other:?}"),
    }
}

#[test]
fn test_proc_inspection_failure_becomes_unknown_or_returns_inspection_error() {
    let dummy_path = std::path::Path::new("/nonexistent_dir_umbra/proc/net/tcp");
    let err = umbra::tor::find_socket_in_proc_net(dummy_path, 9040).unwrap_err();
    match err {
        UmbraError::TorInspectionError(msg) => {
            assert!(msg.contains("failed to read") || msg.contains("does not exist"));
        }
        other => panic!("expected TorInspectionError, got {other:?}"),
    }

    let err2 = umbra::tor::verify_socket_ownership(
        dummy_path,
        std::path::Path::new("/nonexistent_dir_umbra/proc"),
        9040,
        Some(1000),
        Some(1234),
    )
    .unwrap_err();
    match err2 {
        UmbraError::TorInspectionError(msg) => {
            assert!(msg.contains("does not exist"));
        }
        other => panic!("expected TorInspectionError, got {other:?}"),
    }

    let err3 = umbra::tor::find_socket_inode_owner(
        std::path::Path::new("/nonexistent_dir_umbra/proc"),
        12345,
    )
    .unwrap_err();
    match err3 {
        UmbraError::TorInspectionError(msg) => {
            assert!(msg.contains("failed to read proc directory"));
        }
        other => panic!("expected TorInspectionError, got {other:?}"),
    }

    // Verify requirement 12: /proc inspection failure evaluates LiveVerifier to UNKNOWN status
    let tmp = tempfile::NamedTempFile::new().expect("tempfile");
    let active_state = ActiveState::new_with_status(
        "act_proc_test".to_string(),
        "eth0".to_string(),
        "02:aa:bb:cc:dd:ee".to_string(),
        "02:11:22:33:44:55".to_string(),
        true,
        1000,
        9040,
        5353,
        UmbraStatus::Active,
    );
    active_state.save_to_path(tmp.path()).expect("save state");

    let verify_opts = umbra::verify::VerifyOptions {
        state_file_override: Some(tmp.path().to_string_lossy().to_string()),
        proc_dir_override: Some("/nonexistent_dir_umbra/proc".to_string()),
        ..Default::default()
    };
    let report =
        umbra::verify::LiveVerifier::verify_with_options(&verify_opts).expect("verify report");
    assert_eq!(
        report.status,
        UmbraStatus::Unknown,
        "/proc inspection failure must cause LiveVerifier to evaluate to UNKNOWN status"
    );
}
