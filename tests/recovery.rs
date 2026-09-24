use clap::Parser;
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;

use umbra::cli::{Cli, Commands};
use umbra::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME, OWNERSHIP_MARKER};
use umbra::error::UmbraError;
use umbra::firewall::FirewallController;
use umbra::recovery::{RecoveryController, RecoveryOptions};
use umbra::runtime_state::ActiveState;
use umbra::system::ProcessLock;

#[test]
fn test_cli_parse_stop() {
    let cli = Cli::try_parse_from(["umbra", "stop"]).expect("parse stop");
    assert_eq!(cli.command, Commands::Stop);
}

#[test]
fn test_cli_parse_recover_default() {
    let cli = Cli::try_parse_from(["umbra", "recover"]).expect("parse recover default");
    assert_eq!(
        cli.command,
        Commands::Recover {
            normal: false,
            force: false
        }
    );
}

#[test]
fn test_cli_parse_recover_normal() {
    let cli = Cli::try_parse_from(["umbra", "recover", "--normal"]).expect("parse recover normal");
    assert_eq!(
        cli.command,
        Commands::Recover {
            normal: true,
            force: false
        }
    );
}

#[test]
fn test_cli_parse_recover_force() {
    let cli = Cli::try_parse_from(["umbra", "recover", "--force"]).expect("parse recover force");
    assert_eq!(
        cli.command,
        Commands::Recover {
            normal: false,
            force: true
        }
    );
}

#[test]
fn test_cli_parse_recover_conflict() {
    let result = Cli::try_parse_from(["umbra", "recover", "--normal", "--force"]);
    assert!(
        result.is_err(),
        "conflicting --normal and --force flags must be rejected"
    );
}

#[test]
fn test_recovery_options_defaults() {
    let opts = RecoveryOptions::default();
    assert_eq!(opts.state_file_override, None);
    assert_eq!(opts.lock_file_override, None);
    assert_eq!(opts.table_family, NFT_TABLE_FAMILY);
    assert_eq!(opts.table_name, NFT_TABLE_NAME);
}

#[test]
fn test_process_lock_cleanup_path() {
    let tmp = NamedTempFile::new().expect("create temp lock");
    let path = tmp.path().to_path_buf();
    assert!(path.exists());

    // cleanup_path should delete the file
    ProcessLock::cleanup_path(&path).expect("cleanup lock path");
    assert!(!path.exists());

    // cleanup on non-existent file should succeed idempotently
    ProcessLock::cleanup_path(&path).expect("cleanup non-existent");
}

#[test]
fn test_recovery_normal_fails_on_corrupt_state() {
    let mut tmp = NamedTempFile::new().expect("create temp file");
    tmp.write_all(b"{ \"version\": 1, invalid_json")
        .expect("write corrupt json");
    let state_path = tmp.path().to_path_buf();

    // Normal recovery must reject corrupt state with RecoveryUncertain and suggest --force
    let result = RecoveryController::recover_normal_with_state_path(&state_path);
    assert!(result.is_err());
    match result.unwrap_err() {
        UmbraError::RecoveryUncertain(msg) => {
            assert!(msg.contains("Runtime state file is corrupt"));
            assert!(msg.contains("umbra recover --force"));
        }
        other => panic!("expected RecoveryUncertain error, got {other:?}"),
    }

    // Corrupt state file must NOT be deleted by normal recovery to preserve diagnostic evidence
    assert!(state_path.exists());

    // Clean up
    let _ = fs::remove_file(state_path);
}

#[test]
fn test_active_state_corrupt_validation() {
    let invalid_version = ActiveState {
        version: 99,
        activation_id: "test1".to_string(),
        interface: "eth0".to_string(),
        original_mac: "02:00:00:00:00:01".to_string(),
        randomized_mac: "02:00:00:00:00:02".to_string(),
        interface_was_up: true,
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        firewall_identity: "umbra".to_string(),
        created_at_epoch: 1000,
    };
    assert!(invalid_version.validate().is_err());

    let empty_iface = ActiveState {
        version: 1,
        activation_id: "test1".to_string(),
        interface: "   ".to_string(),
        original_mac: "02:00:00:00:00:01".to_string(),
        randomized_mac: "02:00:00:00:00:02".to_string(),
        interface_was_up: true,
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        firewall_identity: "umbra".to_string(),
        created_at_epoch: 1000,
    };
    assert!(empty_iface.validate().is_err());
}

#[test]
fn test_firewall_authenticate_ruleset_text_strict() {
    let valid = format!(
        "table inet umbra {{\n  chain output {{\n    return comment \"{}\"\n  }}\n}}\n",
        OWNERSHIP_MARKER
    );
    assert!(FirewallController::authenticate_ruleset_text(&valid).is_ok());

    let invalid = "table inet umbra {\n  chain output {\n    return comment \"other\"\n  }\n}\n";
    assert!(FirewallController::authenticate_ruleset_text(invalid).is_err());

    assert!(FirewallController::authenticate_ruleset_text("").is_err());
}

#[test]
fn test_active_state_mac_validation_strict() {
    let invalid_orig_mac = ActiveState {
        version: 1,
        activation_id: "test1".to_string(),
        interface: "eth0".to_string(),
        original_mac: "invalid-mac-address".to_string(),
        randomized_mac: "02:00:00:00:00:02".to_string(),
        interface_was_up: true,
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        firewall_identity: "umbra".to_string(),
        created_at_epoch: 1000,
    };
    assert!(invalid_orig_mac.validate().is_err());

    let zero_mac = ActiveState {
        version: 1,
        activation_id: "test1".to_string(),
        interface: "eth0".to_string(),
        original_mac: "00:00:00:00:00:00".to_string(),
        randomized_mac: "02:00:00:00:00:02".to_string(),
        interface_was_up: true,
        tor_uid: 1000,
        tor_transport_port: 9040,
        tor_dns_port: 5353,
        firewall_identity: "umbra".to_string(),
        created_at_epoch: 1000,
    };
    assert!(zero_mac.validate().is_err());
}

#[test]
fn test_recovery_options_resolved_lock_path() {
    // 1. Default points to LOCK_FILE
    let default_opts = RecoveryOptions::default();
    assert_eq!(
        default_opts.resolved_lock_path().to_string_lossy(),
        umbra::constants::LOCK_FILE
    );

    // 2. Explicit lock_file_override is honored
    let custom_lock_opts = RecoveryOptions {
        lock_file_override: Some("/tmp/custom.lock".to_string()),
        ..Default::default()
    };
    assert_eq!(
        custom_lock_opts.resolved_lock_path().to_string_lossy(),
        "/tmp/custom.lock"
    );

    // 3. state_file_override isolates lock path if lock_file_override is None
    let state_opts = RecoveryOptions {
        state_file_override: Some("/tmp/my_state.json".to_string()),
        ..Default::default()
    };
    assert_eq!(
        state_opts.resolved_lock_path().to_string_lossy(),
        "/tmp/my_state.lock"
    );
}

#[test]
fn test_extract_json_field_helpers() {
    use umbra::recovery::extract_json_field;

    let json = r#"{"interface": "eth0", "original_mac": "02:11:22:33:44:55", "version": 1}"#;
    assert_eq!(
        extract_json_field(json, "interface"),
        Some("eth0".to_string())
    );
    assert_eq!(
        extract_json_field(json, "original_mac"),
        Some("02:11:22:33:44:55".to_string())
    );
    assert_eq!(extract_json_field(json, "nonexistent"), None);

    // Corrupted trailing JSON
    let damaged = r#"{"interface": "wlan0", "original_mac": "02:aa:bb:cc:dd:ee", broken... "#;
    assert_eq!(
        extract_json_field(damaged, "interface"),
        Some("wlan0".to_string())
    );
    assert_eq!(
        extract_json_field(damaged, "original_mac"),
        Some("02:aa:bb:cc:dd:ee".to_string())
    );
}

#[test]
fn test_recovery_controller_concurrency_lock() {
    let tmp = NamedTempFile::new().expect("create temp lock");
    let lock_path = tmp.path().to_string_lossy().to_string();

    // Acquire lock explicitly
    let guard = ProcessLock::acquire_path(std::path::Path::new(&lock_path)).expect("acquire lock");

    // RecoveryController must fail while lock is held
    let opts = RecoveryOptions {
        lock_file_override: Some(lock_path.clone()),
        state_file_override: Some("/tmp/nonexistent_rec_conc_test.json".to_string()),
        ..Default::default()
    };

    let stop_res = RecoveryController::stop_with_options(&opts);
    assert!(stop_res.is_err());
    match stop_res.unwrap_err() {
        UmbraError::LockAcquisitionFailed(_) => {}
        other => panic!("expected LockAcquisitionFailed, got {other:?}"),
    }

    let rec_res = RecoveryController::recover_normal_with_options(&opts);
    assert!(rec_res.is_err());
    match rec_res.unwrap_err() {
        UmbraError::LockAcquisitionFailed(_) => {}
        other => panic!("expected LockAcquisitionFailed, got {other:?}"),
    }

    let force_res = RecoveryController::recover_force_with_options(&opts);
    assert!(force_res.is_err());
    match force_res.unwrap_err() {
        UmbraError::LockAcquisitionFailed(_) => {}
        other => panic!("expected LockAcquisitionFailed, got {other:?}"),
    }

    drop(guard);
}
