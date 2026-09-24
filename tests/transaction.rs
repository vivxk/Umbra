use tempfile::NamedTempFile;
use umbra::constants::{DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT};
use umbra::error::UmbraError;
use umbra::runtime_state::ActiveState;
use umbra::transaction::{StartupTransaction, StartupTransactionOptions};

#[test]
fn test_startup_options_defaults() {
    let opts = StartupTransactionOptions::default();
    assert!(opts.interface_override.is_none());
    assert_eq!(opts.transport_port, DEFAULT_TOR_TRANSPORT);
    assert_eq!(opts.dns_port, DEFAULT_TOR_DNSPORT);
    assert!(opts.state_file_override.is_none());
}

#[test]
fn test_startup_rejects_already_active_session() {
    let tmp = NamedTempFile::new().expect("create temp state file");
    let active_state = ActiveState::new(
        "act_existing_999".to_string(),
        "eth0".to_string(),
        "00:11:22:33:44:55".to_string(),
        "02:11:22:33:44:55".to_string(),
        true,
        122,
        9040,
        5353,
        "umbra".to_string(),
    );
    active_state
        .save_to_path(tmp.path())
        .expect("save active state");

    let opts = StartupTransactionOptions {
        interface_override: Some("eth0".to_string()),
        transport_port: 9040,
        dns_port: 5353,
        state_file_override: Some(tmp.path().to_string_lossy().to_string()),
    };

    let result = StartupTransaction::execute(opts);
    assert!(result.is_err());
    match result.unwrap_err() {
        UmbraError::AlreadyActive {
            interface,
            activation_id,
        } => {
            assert_eq!(interface, "eth0");
            assert_eq!(activation_id, "act_existing_999");
        }
        other => panic!("expected AlreadyActive error, got {other:?}"),
    }
}

#[test]
fn test_startup_fails_closed_when_tor_is_not_running() {
    let tmp = NamedTempFile::new().expect("create temp state file");
    // Ensure state file is deleted so it's fresh
    let path = tmp.path().to_path_buf();
    drop(tmp);

    let opts = StartupTransactionOptions {
        interface_override: Some("nonexistent_device_xyz".to_string()),
        transport_port: 65432, // Non-existent port
        dns_port: 65433,
        state_file_override: Some(path.to_string_lossy().to_string()),
    };

    let result = StartupTransaction::execute(opts);
    assert!(result.is_err());
    // Must NOT create or save active state
    assert!(!path.exists());
}
