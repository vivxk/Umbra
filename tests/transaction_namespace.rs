mod common;

use std::process::Command;
use tempfile::NamedTempFile;

use common::{is_in_isolated_netns, IsolatedNetns};
use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME};
use umbra::error::UmbraError;
use umbra::firewall::FirewallController;
use umbra::interface::InterfaceController;
use umbra::mac::MacAddress;
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
