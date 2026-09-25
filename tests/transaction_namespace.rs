mod common;

use std::fs;
use std::process::Command;
use tempfile::NamedTempFile;

use common::{is_in_isolated_netns, IsolatedNetns};
use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME};
use umbra::error::UmbraError;
use umbra::firewall::{FirewallConfig, FirewallController};
use umbra::interface::{InterfaceBaseline, InterfaceController};
use umbra::mac::MacAddress;
use umbra::runtime_state::{ActiveState, UmbraStatus};
use umbra::system::ProcessLock;
use umbra::transaction::{StartupTransaction, StartupTransactionOptions};

#[test]
fn test_process_lock_concurrency_prevention() {
    let _guard1 = match ProcessLock::acquire() {
        Ok(g) => g,
        Err(UmbraError::LockAcquisitionFailed(_)) => return,
        Err(other) => panic!("expected LockAcquisitionFailed, got {other:?}"),
    };

    // Second acquisition attempt must fail
    match ProcessLock::acquire() {
        Err(UmbraError::LockAcquisitionFailed(_)) => {}
        other => panic!("expected LockAcquisitionFailed on concurrent acquisition, got {other:?}"),
    }
}

#[test]
fn test_startup_preflight_tor_missing_fails_closed_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("trans_preflight") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_startup_preflight_tor_missing_fails_closed_in_netns");
        return;
    }

    // Inside isolated network namespace: create a dummy test interface
    let dev_name = "dum_trans0";
    let orig_mac_str = "02:aa:bb:cc:dd:01";
    let _ = Command::new("ip")
        .args([
            "link",
            "add",
            dev_name,
            "address",
            orig_mac_str,
            "type",
            "dummy",
        ])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", dev_name, "up"])
        .status();

    let tmp = NamedTempFile::new().expect("create temp state file");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    let opts = StartupTransactionOptions {
        interface_override: Some(dev_name.to_string()),
        transport_port: 9040,
        dns_port: 5353,
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    // Execute startup transaction with no Tor process running
    let result = StartupTransaction::execute(opts);
    assert!(result.is_err());

    // 1. Invariant: Original interface MAC must remain unchanged (no leak or premature mutation)
    let current_mac = InterfaceController::read_mac(dev_name).expect("read live mac");
    assert_eq!(
        current_mac,
        MacAddress::parse(orig_mac_str).unwrap(),
        "MAC must NOT be mutated if pre-flight Tor checks fail"
    );

    // 2. Invariant: Firewall table inet umbra must NOT be left installed
    assert!(
        !FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "table inet umbra must not be installed if pre-flight fails"
    );

    // 3. Invariant: State file must not be committed
    assert!(!state_path.exists());

    // Cleanup dummy interface
    let _ = Command::new("ip").args(["link", "del", dev_name]).status();
}

#[test]
fn test_startup_rejects_orphan_table_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("trans_orphan") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_startup_rejects_orphan_table_in_netns");
        return;
    }

    // Pre-create an orphan table inet umbra in netns
    let _ = Command::new("nft")
        .args(["add", "table", "inet", "umbra"])
        .status();

    let opts = StartupTransactionOptions {
        interface_override: Some("lo".to_string()),
        transport_port: 9040,
        dns_port: 5353,
        state_file_override: None,
        ..Default::default()
    };

    let result = StartupTransaction::execute(opts);
    assert!(result.is_err());
    match result.unwrap_err() {
        UmbraError::FirewallOwnershipUnknown(msg) => {
            assert!(msg.contains("table inet umbra is already present"));
        }
        other => panic!("expected FirewallOwnershipUnknown error, got {other:?}"),
    }

    // Clean up
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "umbra"])
        .status();
}

#[test]
fn test_interface_restoration_failure_during_rollback_keeps_recovery_state_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("trans_rollback_err") {
            Some(ns) => ns,
            None => return,
        };
        netns.run_test(
            "test_interface_restoration_failure_during_rollback_keeps_recovery_state_in_netns",
        );
        return;
    }

    let dev_name = "dum_nonexistent_rb";
    let orig_mac = MacAddress::parse("02:aa:bb:cc:dd:99").unwrap();
    let baseline = InterfaceBaseline {
        name: dev_name.to_string(),
        original_mac: orig_mac,
        was_up: true,
    };

    let fw_config = FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        tor_control_port: 9051,
        egress_interface: dev_name.to_string(),
        activation_id: "act_rb_test".to_string(),
    };

    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    let tmp = NamedTempFile::new().expect("create temp state file");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    let mut active_state = ActiveState::new_with_status(
        fw_config.activation_id.clone(),
        dev_name.to_string(),
        orig_mac.to_string(),
        "02:99:aa:bb:cc:dd".to_string(),
        true,
        fw_config.tor_uid,
        fw_config.tor_transport_port,
        fw_config.tor_dns_port,
        fw_config.table_name.clone(),
        UmbraStatus::Starting,
    );
    active_state.save_to_path(&state_path).expect("save state");

    // Invoke rollback with mac_randomized = true, firewall_installed = true
    let res = StartupTransaction::rollback(
        &baseline,
        &fw_config,
        true,
        true,
        &state_path,
        &mut active_state,
    );

    assert!(
        res.is_err(),
        "rollback must fail when interface cannot be restored"
    );
    match res.unwrap_err() {
        UmbraError::RecoveryUncertain(msg) => {
            assert!(msg.contains("failed to restore baseline MAC"));
        }
        other => panic!("expected RecoveryUncertain, got {other:?}"),
    }

    // Invariants:
    // 1. State file exists on disk
    assert!(state_path.exists(), "State file must be preserved");
    let loaded = ActiveState::load_from_path(&state_path)
        .unwrap()
        .expect("loaded state");
    // 2. State status is RecoveryRequired
    assert_eq!(
        loaded.status,
        UmbraStatus::RecoveryRequired,
        "Status must be RecoveryRequired after rollback interface failure"
    );
    // 3. Firewall table remains intact in kernel
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "Firewall table must remain intact after rollback interface failure"
    );

    // Clean up
    let _ = fs::remove_file(state_path);
    let _ = FirewallController::teardown_with_id(
        &fw_config.table_family,
        &fw_config.table_name,
        Some(&fw_config.activation_id),
    );
}
