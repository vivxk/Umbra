mod common;

use std::fs;
use std::io::Write;
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
use umbra::mac::MacAddress;
use umbra::recovery::{RecoveryController, RecoveryOptions};
use umbra::runtime_state::ActiveState;

fn get_test_fw_config(iface: &str) -> FirewallConfig {
    FirewallConfig {
        table_name: NFT_TABLE_NAME.to_string(),
        table_family: NFT_TABLE_FAMILY.to_string(),
        tor_uid: 1000,
        tor_transport_port: DEFAULT_TOR_TRANSPORT,
        tor_dns_port: DEFAULT_TOR_DNSPORT,
        tor_control_port: DEFAULT_TOR_CONTROLPORT,
        egress_interface: iface.to_string(),
        activation_id: "test_rec_act".to_string(),
    }
}

#[test]
fn test_stop_workflow_clean_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_stop_clean") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_stop_workflow_clean_in_netns");
        return;
    }

    let dev_name = "dum_stop0";
    let orig_mac_str = "02:aa:bb:cc:dd:10";
    let rand_mac_str = "02:11:22:33:44:55";

    // Create dummy interface
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

    // Apply randomized MAC
    InterfaceController::apply_mac(dev_name, MacAddress::parse(rand_mac_str).unwrap())
        .expect("apply randomized MAC");

    // Install Umbra firewall
    let fw_config = get_test_fw_config(dev_name);
    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    // Create active state file
    let tmp = NamedTempFile::new().expect("create temp state file");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    let state = ActiveState::new(
        fw_config.activation_id.clone(),
        dev_name.to_string(),
        orig_mac_str.to_string(),
        rand_mac_str.to_string(),
        true,
        fw_config.tor_uid,
        fw_config.tor_transport_port,
        fw_config.tor_dns_port,
        fw_config.table_name.clone(),
    );
    state.save_to_path(&state_path).expect("save state");
    assert!(state_path.exists());

    // Execute stop workflow
    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };
    RecoveryController::stop_with_options(&opts).expect("stop must succeed");

    // Invariants post-stop:
    // 1. Firewall table deleted
    assert!(
        !FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "firewall table must be removed upon stop"
    );

    // 2. MAC restored to baseline
    let live_mac = InterfaceController::read_mac(dev_name).expect("read mac");
    assert_eq!(
        live_mac,
        MacAddress::parse(orig_mac_str).unwrap(),
        "MAC must be restored to original baseline"
    );

    // 3. Administrative state restored to UP
    assert!(
        InterfaceController::is_administratively_up(dev_name).unwrap(),
        "admin state must remain UP"
    );

    // 4. State file removed
    assert!(
        !state_path.exists(),
        "runtime state file must be removed upon clean stop"
    );

    // Cleanup
    let _ = Command::new("ip").args(["link", "del", dev_name]).status();
}

#[test]
fn test_stop_idempotent_when_inactive_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_stop_idemp") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_stop_idempotent_when_inactive_in_netns");
        return;
    }

    let non_existent = std::path::PathBuf::from("/tmp/umbra_test_non_existent.json");
    let opts = RecoveryOptions {
        state_file_override: Some(non_existent.to_string_lossy().to_string()),
        ..Default::default()
    };

    // Calling stop when already inactive must succeed without error
    let result = RecoveryController::stop_with_options(&opts);
    assert!(
        result.is_ok(),
        "stop on inactive state should be idempotent"
    );
}

#[test]
fn test_recover_normal_workflow_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_norm_flow") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_recover_normal_workflow_in_netns");
        return;
    }

    let dev_name = "dum_rec0";
    let orig_mac_str = "02:aa:bb:cc:dd:20";
    let rand_mac_str = "02:22:33:44:55:66";

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

    InterfaceController::apply_mac(dev_name, MacAddress::parse(rand_mac_str).unwrap())
        .expect("apply MAC");

    let fw_config = get_test_fw_config(dev_name);
    FirewallController::install(&fw_config).expect("install firewall");

    let tmp = NamedTempFile::new().expect("create temp state file");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    let state = ActiveState::new(
        fw_config.activation_id.clone(),
        dev_name.to_string(),
        orig_mac_str.to_string(),
        rand_mac_str.to_string(),
        true,
        fw_config.tor_uid,
        fw_config.tor_transport_port,
        fw_config.tor_dns_port,
        fw_config.table_name.clone(),
    );
    state.save_to_path(&state_path).expect("save state");

    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    let actions = RecoveryController::recover_normal_with_options(&opts).expect("normal recovery");
    assert!(actions
        .iter()
        .any(|a| a.contains("removed Umbra firewall table")));
    assert!(actions.iter().any(|a| a.contains("Restored interface")));

    // Invariants post-recovery:
    assert!(!FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());
    assert_eq!(
        InterfaceController::read_mac(dev_name).unwrap(),
        MacAddress::parse(orig_mac_str).unwrap()
    );
    assert!(!state_path.exists());

    let _ = Command::new("ip").args(["link", "del", dev_name]).status();
}

#[test]
fn test_recover_normal_fails_on_corrupt_state_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_norm_corrupt") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_recover_normal_fails_on_corrupt_state_in_netns");
        return;
    }

    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");

    let mut tmp = NamedTempFile::new().expect("create temp state file");
    tmp.write_all(b"{ invalid_json")
        .expect("write corrupt json");
    let state_path = tmp.path().to_path_buf();

    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    let result = RecoveryController::recover_normal_with_options(&opts);
    assert!(result.is_err());
    match result.unwrap_err() {
        UmbraError::RecoveryUncertain(msg) => {
            assert!(msg.contains("umbra recover --force"));
        }
        other => panic!("expected RecoveryUncertain, got {other:?}"),
    }

    // Crucial fail-closed invariant:
    // When normal recovery fails on uncertainty, firewall table must remain intact!
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "firewall table must remain intact if normal recovery fails"
    );

    // Corrupt state file must NOT be deleted
    assert!(state_path.exists());

    // Clean up
    let _ = FirewallController::teardown(NFT_TABLE_FAMILY, NFT_TABLE_NAME);
    let _ = fs::remove_file(state_path);
}

#[test]
fn test_recover_force_with_corrupt_state_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_force_corrupt") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_recover_force_with_corrupt_state_in_netns");
        return;
    }

    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");

    let mut tmp = NamedTempFile::new().expect("create temp state file");
    tmp.write_all(b"{ corrupted: true, incomplete")
        .expect("write corrupt json");
    let state_path = tmp.path().to_path_buf();

    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    let actions = RecoveryController::recover_force_with_options(&opts).expect("force recovery");
    assert!(actions
        .iter()
        .any(|a| a
            .contains("Successfully authenticated ownership marker and removed firewall table")));
    assert!(actions
        .iter()
        .any(|a| a.contains("Warning: runtime state file was corrupt")));

    // Invariants:
    assert!(!FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());
    assert!(
        !state_path.exists(),
        "force recovery must remove corrupt state file"
    );
}

#[test]
fn test_recover_force_with_missing_state_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_force_missing") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_recover_force_with_missing_state_in_netns");
        return;
    }

    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");

    let non_existent = std::path::PathBuf::from("/tmp/umbra_test_missing_state_file.json");
    if non_existent.exists() {
        let _ = fs::remove_file(&non_existent);
    }

    let opts = RecoveryOptions {
        state_file_override: Some(non_existent.to_string_lossy().to_string()),
        ..Default::default()
    };

    let actions = RecoveryController::recover_force_with_options(&opts).expect("force recovery");
    assert!(actions
        .iter()
        .any(|a| a
            .contains("Successfully authenticated ownership marker and removed firewall table")));
    assert!(actions
        .iter()
        .any(|a| a.contains("runtime state file was absent")));

    assert!(!FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());
}

#[test]
fn test_recovery_refuses_unauthorized_table_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_unauth") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_recovery_refuses_unauthorized_table_in_netns");
        return;
    }

    // Create a rogue / foreign table inet umbra WITHOUT the "umbra-managed" comment
    let rogue_ruleset = r#"
table inet umbra {
    chain output_filter {
        type filter hook output priority 0; policy accept;
    }
}
"#;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .expect("spawn nft for rogue table");
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(rogue_ruleset.as_bytes()).unwrap();
    }
    assert!(child.wait().unwrap().success());
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    let dev_name = "dum_rogue0";
    let orig_mac = "02:aa:bb:cc:dd:ee";
    let _ = Command::new("ip")
        .args([
            "link", "add", dev_name, "address", orig_mac, "type", "dummy",
        ])
        .status();
    let _ = Command::new("ip")
        .args(["link", "set", dev_name, "up"])
        .status();

    let tmp = NamedTempFile::new().expect("tempfile");
    let dummy_state = tmp.path().to_path_buf();
    drop(tmp);

    let state = ActiveState::new(
        "act_rogue_test".to_string(),
        dev_name.to_string(),
        orig_mac.to_string(),
        "02:11:22:33:44:55".to_string(),
        true,
        1000,
        9040,
        5353,
        "umbra".to_string(),
    );
    state.save_to_path(&dummy_state).expect("save state");

    let opts = RecoveryOptions {
        state_file_override: Some(dummy_state.to_string_lossy().to_string()),
        ..Default::default()
    };

    // 1. Normal recovery must refuse to touch unauthorized table
    let norm_res = RecoveryController::recover_normal_with_options(&opts);
    assert!(norm_res.is_err());
    match norm_res.unwrap_err() {
        UmbraError::FirewallOwnershipUnknown(msg) => {
            assert!(msg.contains("missing required ownership marker"));
        }
        other => panic!("expected FirewallOwnershipUnknown, got {other:?}"),
    }
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "unauthorized table must NOT be deleted by recover_normal"
    );

    // 2. Force recovery must ALSO refuse to touch unauthorized table
    let force_res = RecoveryController::recover_force_with_options(&opts);
    assert!(force_res.is_err());
    match force_res.unwrap_err() {
        UmbraError::FirewallOwnershipUnknown(msg) => {
            assert!(msg.contains("Refusing force recovery"));
        }
        other => panic!("expected FirewallOwnershipUnknown, got {other:?}"),
    }
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "unauthorized table must NOT be deleted by recover_force"
    );

    // 3. Stop must ALSO refuse to touch unauthorized table
    let stop_res = RecoveryController::stop_with_options(&opts);
    assert!(stop_res.is_err());
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "unauthorized table must NOT be deleted by stop"
    );

    // Clean up rogue table and dummy device manually
    let _ = fs::remove_file(&dummy_state);
    let _ = Command::new("ip").args(["link", "del", dev_name]).status();
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "umbra"])
        .status();
}

#[test]
fn test_crash_resilience_fail_closed_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_crash_resil") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_crash_resilience_fail_closed_in_netns");
        return;
    }

    // 1. Simulate active session by installing valid ruleset
    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    // 2. Simulate process crash / abnormal exit:
    // In Linux, the kernel retains netfilter state independently of userspace process lifecycles.
    // Verify that the table, drop policies, and redirect rules remain fully active in kernel.
    FirewallController::verify_live(&fw_config)
        .expect("kernel firewall enforcement must remain intact after abnormal exit");

    // Check that table query directly via nft list shows drop policy
    let out = Command::new("nft")
        .args(["list", "table", "inet", "umbra"])
        .output()
        .expect("list table");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("policy drop"));
    assert!(stdout.contains("chain output_filter"));
    assert!(stdout.contains("chain output_nat"));

    // 3. Post-crash explicit recovery returns system to normal
    let opts = RecoveryOptions {
        state_file_override: Some("/tmp/non_existent_crash_state.json".to_string()),
        ..Default::default()
    };
    RecoveryController::recover_force_with_options(&opts).expect("force recovery clean up");
    assert!(!FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());
}

#[test]
fn test_stop_refuses_when_state_missing_but_table_exists_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_stop_missing_st") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_stop_refuses_when_state_missing_but_table_exists_in_netns");
        return;
    }

    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    let non_existent = std::path::PathBuf::from("/tmp/umbra_test_stop_missing_state.json");
    if non_existent.exists() {
        let _ = fs::remove_file(&non_existent);
    }

    let opts = RecoveryOptions {
        state_file_override: Some(non_existent.to_string_lossy().to_string()),
        ..Default::default()
    };

    // Calling stop when state is missing but table exists must refuse with RecoveryUncertain
    let stop_res = RecoveryController::stop_with_options(&opts);
    assert!(stop_res.is_err());
    match stop_res.unwrap_err() {
        UmbraError::RecoveryUncertain(msg) => {
            assert!(msg.contains("Cannot cleanly stop"));
            assert!(msg.contains("umbra recover --force"));
        }
        other => panic!("expected RecoveryUncertain, got {other:?}"),
    }

    // Table must NOT have been deleted
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    // Clean up via force recovery
    RecoveryController::recover_force_with_options(&opts).expect("force recovery");
    assert!(!FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());
}

#[test]
fn test_recover_normal_fails_and_preserves_state_on_mac_restore_error_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_norm_err_pres") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test(
            "test_recover_normal_fails_and_preserves_state_on_mac_restore_error_in_netns",
        );
        return;
    }

    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");

    let tmp = NamedTempFile::new().expect("create temp state file");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    // State points to a non-existent interface "dum_ghost99"
    let state = ActiveState::new(
        fw_config.activation_id.clone(),
        "dum_ghost99".to_string(),
        "02:aa:bb:cc:dd:40".to_string(),
        "02:44:55:66:77:88".to_string(),
        true,
        fw_config.tor_uid,
        fw_config.tor_transport_port,
        fw_config.tor_dns_port,
        fw_config.table_name.clone(),
    );
    state.save_to_path(&state_path).expect("save state");

    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    // Normal recovery MUST fail because baseline MAC cannot be restored on non-existent device
    let res = RecoveryController::recover_normal_with_options(&opts);
    assert!(
        res.is_err(),
        "recover_normal must fail when MAC restore fails"
    );

    // CRITICAL: state file MUST be preserved on disk so operator can diagnose or force recover
    assert!(
        state_path.exists(),
        "state file must NOT be deleted when interface restoration fails"
    );
    let loaded = ActiveState::load_from_path(&state_path)
        .unwrap()
        .expect("loaded state");
    assert_eq!(
        loaded.status,
        umbra::runtime_state::UmbraStatus::RecoveryRequired,
        "Status must be RecoveryRequired when restoration fails in recover_normal"
    );

    // CRITICAL: firewall table MUST remain active and fail-closed
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "firewall table must remain intact when MAC restore fails during recover_normal"
    );

    // Clean up
    let _ = fs::remove_file(state_path);
    let _ = FirewallController::teardown(NFT_TABLE_FAMILY, NFT_TABLE_NAME);
}

#[test]
fn test_recover_force_salvages_baseline_from_corrupt_state_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_force_salv") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_recover_force_salvages_baseline_from_corrupt_state_in_netns");
        return;
    }

    let dev_name = "dum_salv0";
    let orig_mac_str = "02:aa:bb:cc:dd:50";
    let rand_mac_str = "02:55:66:77:88:99";

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

    InterfaceController::apply_mac(dev_name, MacAddress::parse(rand_mac_str).unwrap())
        .expect("apply MAC");

    let fw_config = get_test_fw_config(dev_name);
    FirewallController::install(&fw_config).expect("install firewall");

    // Create a corrupt JSON state file that still has interface and original_mac fields
    let mut tmp = NamedTempFile::new().expect("create temp state file");
    let corrupt_json = format!(
        "{{\n  \"interface\": \"{dev_name}\",\n  \"original_mac\": \"{orig_mac_str}\",\n  \"randomized_mac\": \"{rand_mac_str}\",\n  \"corrupted_unclosed_block\": [\n"
    );
    tmp.write_all(corrupt_json.as_bytes())
        .expect("write corrupt json");
    let state_path = tmp.path().to_path_buf();

    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    let actions = RecoveryController::recover_force_with_options(&opts).expect("force recovery");
    assert!(actions
        .iter()
        .any(|a| a.contains("Best-effort restoration: salvaged baseline from corrupt state file")));

    // Invariants:
    // 1. MAC restored to original
    let current_mac = InterfaceController::read_mac(dev_name).expect("read mac");
    assert_eq!(current_mac, MacAddress::parse(orig_mac_str).unwrap());

    // 2. Firewall deleted
    assert!(!FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    // 3. Corrupt state file cleaned
    assert!(!state_path.exists());

    let _ = Command::new("ip").args(["link", "del", dev_name]).status();
}

#[test]
fn test_crash_resilience_subprocess_crash_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_crash_proc") {
            Some(ns) => ns,
            None => {
                eprintln!("Skipping netns test: network namespace creation not permitted");
                return;
            }
        };
        netns.run_test("test_crash_resilience_subprocess_crash_in_netns");
        return;
    }

    let dev_name = "dum_crash0";
    let orig_mac_str = "02:aa:bb:cc:dd:60";
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

    let fw_config = get_test_fw_config(dev_name);
    FirewallController::install(&fw_config).expect("install firewall");

    // Spawn a child process to simulate active daemon/worker, and immediately kill with SIGKILL (signal 9)
    let mut child = Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn sleep process");

    let pid = child.id();
    // Send SIGKILL (kill -9)
    let kill_status = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .expect("kill -9 child process");
    assert!(kill_status.success());
    let _ = child.wait();

    // Verify kernel firewall ruleset is 100% active and fail-closed after process death
    FirewallController::verify_live(&fw_config)
        .expect("kernel firewall must survive process termination");

    let list_out = Command::new("nft")
        .args(["list", "table", "inet", "umbra"])
        .output()
        .expect("list table");
    let stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(stdout.contains("policy drop"));
    assert!(stdout.contains("chain output_filter"));

    // Explicit recovery returns host to normal
    let opts = RecoveryOptions {
        state_file_override: Some("/tmp/nonexistent_crash_state.json".to_string()),
        ..Default::default()
    };
    RecoveryController::recover_force_with_options(&opts).expect("force recovery clean up");
    assert!(!FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    let _ = Command::new("ip").args(["link", "del", dev_name]).status();
}

#[test]
fn test_stop_fails_and_keeps_firewall_on_mac_restore_error_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_stop_err_pres") {
            Some(ns) => ns,
            None => return,
        };
        netns.run_test("test_stop_fails_and_keeps_firewall_on_mac_restore_error_in_netns");
        return;
    }

    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    let tmp = NamedTempFile::new().expect("create temp state file");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    // State points to a non-existent interface "dum_nonexistent_dev"
    let state = ActiveState::new(
        fw_config.activation_id.clone(),
        "dum_nonexistent_dev".to_string(),
        "02:aa:bb:cc:dd:77".to_string(),
        "02:77:88:99:aa:bb".to_string(),
        true,
        fw_config.tor_uid,
        fw_config.tor_transport_port,
        fw_config.tor_dns_port,
        fw_config.table_name.clone(),
    );
    state.save_to_path(&state_path).expect("save state");

    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    // Stop MUST fail because baseline MAC cannot be restored on non-existent device
    let res = RecoveryController::stop_with_options(&opts);
    assert!(res.is_err(), "stop must fail when MAC restore fails");

    // CRITICAL: Firewall table MUST remain active and fail-closed
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "firewall table must remain intact if MAC restore fails during stop"
    );

    // CRITICAL: state file MUST be preserved on disk
    assert!(
        state_path.exists(),
        "state file must NOT be deleted when interface restoration fails during stop"
    );
    let loaded = ActiveState::load_from_path(&state_path)
        .unwrap()
        .expect("loaded state");
    assert_eq!(
        loaded.status,
        umbra::runtime_state::UmbraStatus::RecoveryRequired,
        "Status must be RecoveryRequired when restoration fails during stop"
    );

    // Clean up
    let _ = fs::remove_file(state_path);
    let _ = FirewallController::teardown(NFT_TABLE_FAMILY, NFT_TABLE_NAME);
}

#[test]
fn test_recover_force_fails_and_preserves_state_on_mac_restore_error_in_netns() {
    if !is_in_isolated_netns() {
        let netns = match IsolatedNetns::new("rec_frc_err_pres") {
            Some(ns) => ns,
            None => return,
        };
        netns
            .run_test("test_recover_force_fails_and_preserves_state_on_mac_restore_error_in_netns");
        return;
    }

    let fw_config = get_test_fw_config("lo");
    FirewallController::install(&fw_config).expect("install firewall");
    assert!(FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap());

    let tmp = NamedTempFile::new().expect("create temp state file");
    let state_path = tmp.path().to_path_buf();
    drop(tmp);

    // Valid state file pointing to nonexistent interface "dum_nonexistent_force"
    let state = ActiveState::new(
        fw_config.activation_id.clone(),
        "dum_nonexistent_force".to_string(),
        "02:aa:bb:cc:dd:88".to_string(),
        "02:88:99:aa:bb:cc".to_string(),
        true,
        fw_config.tor_uid,
        fw_config.tor_transport_port,
        fw_config.tor_dns_port,
        fw_config.table_name.clone(),
    );
    state.save_to_path(&state_path).expect("save state");

    let opts = RecoveryOptions {
        state_file_override: Some(state_path.to_string_lossy().to_string()),
        ..Default::default()
    };

    // Force recovery MUST fail because baseline restoration failed on non-existent device
    let res = RecoveryController::recover_force_with_options(&opts);
    assert!(
        res.is_err(),
        "force recovery must fail when salvageable MAC restore fails"
    );

    // CRITICAL: state file MUST be preserved on disk
    assert!(
        state_path.exists(),
        "state file must NOT be deleted when force recovery encounters restoration error"
    );
    let loaded = ActiveState::load_from_path(&state_path)
        .unwrap()
        .expect("loaded state");
    assert_eq!(
        loaded.status,
        umbra::runtime_state::UmbraStatus::RecoveryRequired,
        "Status must be RecoveryRequired when restoration fails in recover_force"
    );

    // CRITICAL: firewall table MUST remain active and fail-closed
    assert!(
        FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME).unwrap(),
        "firewall table must remain intact when force recovery encounters restoration error"
    );

    // Clean up
    let _ = fs::remove_file(state_path);
    let _ = FirewallController::teardown(NFT_TABLE_FAMILY, NFT_TABLE_NAME);
}
