use tempfile::NamedTempFile;
use umbra::runtime_state::{ActiveState, UmbraStatus};

#[test]
fn test_status_display() {
    assert_eq!(UmbraStatus::Active.to_string(), "ACTIVE");
    assert_eq!(UmbraStatus::Inactive.to_string(), "INACTIVE");
    assert_eq!(UmbraStatus::Starting.to_string(), "STARTING");
    assert_eq!(
        UmbraStatus::RecoveryRequired.to_string(),
        "RECOVERY_REQUIRED"
    );
    assert_eq!(UmbraStatus::Unknown.to_string(), "UNKNOWN");
}

#[test]
fn test_state_validation_valid() {
    let state = ActiveState::new(
        "act_123".to_string(),
        "eth0".to_string(),
        "00:15:5d:d8:1e:d5".to_string(),
        "02:15:5d:d8:1e:d5".to_string(),
        true,
        122,
        9040,
        5353,
    );

    assert!(state.validate().is_ok());
}

#[test]
fn test_state_validation_empty_fields_fail() {
    let mut state = ActiveState::new(
        "act_123".to_string(),
        "eth0".to_string(),
        "00:15:5d:d8:1e:d5".to_string(),
        "02:15:5d:d8:1e:d5".to_string(),
        true,
        122,
        9040,
        5353,
    );

    state.activation_id = "".to_string();
    assert!(state.validate().is_err());

    state.activation_id = "act_123".to_string();
    state.interface = "".to_string();
    assert!(state.validate().is_err());

    state.interface = "eth0".to_string();
    state.tor_transport_port = 0;
    assert!(state.validate().is_err());
}

#[test]
fn test_state_save_and_load_roundtrip() {
    let tmp = NamedTempFile::new().expect("create temp file");
    let state = ActiveState::new(
        "act_test_99".to_string(),
        "wlan0".to_string(),
        "11:22:33:44:55:66".to_string(),
        "02:22:33:44:55:66".to_string(),
        false,
        1000,
        9040,
        5353,
    );

    state.save_to_path(tmp.path()).expect("save must succeed");

    let loaded = ActiveState::load_from_path(tmp.path())
        .expect("load must succeed")
        .expect("state must be present");

    assert_eq!(loaded, state);
}

#[test]
fn test_state_deserialization_requires_status() {
    let json_missing_status = r#"{
        "version": 1,
        "activation_id": "act_123",
        "interface": "eth0",
        "original_mac": "00:15:5d:d8:1e:d5",
        "randomized_mac": "02:15:5d:d8:1e:d5",
        "interface_was_up": true,
        "tor_uid": 122,
        "tor_transport_port": 9040,
        "tor_dns_port": 5353
    }"#;

    let res: std::result::Result<ActiveState, serde_json::Error> =
        serde_json::from_str(json_missing_status);
    assert!(
        res.is_err(),
        "Missing status must fail deserialization rather than defaulting to Active"
    );
}
