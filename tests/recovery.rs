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
