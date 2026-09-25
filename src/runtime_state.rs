//! Volatile runtime state machine and serialization for Umbra.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::constants::RUNTIME_STATE_FILE;
use crate::error::{Result, UmbraError};
use crate::mac::MacAddress;

/// High-level lifecycle states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UmbraStatus {
    Inactive,
    Starting,
    Active,
    RecoveryRequired,
    Unknown,
}

impl fmt::Display for UmbraStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inactive => write!(f, "INACTIVE"),
            Self::Starting => write!(f, "STARTING"),
            Self::Active => write!(f, "ACTIVE"),
            Self::RecoveryRequired => write!(f, "RECOVERY_REQUIRED"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Minimal volatile state stored in /run/umbra/active.json
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveState {
    pub version: u32,
    pub activation_id: String,
    pub status: UmbraStatus,
    pub interface: String,
    pub original_mac: String,
    pub randomized_mac: String,
    pub interface_was_up: bool,
    pub tor_uid: u32,
    pub tor_transport_port: u16,
    pub tor_dns_port: u16,
}

impl ActiveState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        activation_id: String,
        interface: String,
        original_mac: String,
        randomized_mac: String,
        interface_was_up: bool,
        tor_uid: u32,
        tor_transport_port: u16,
        tor_dns_port: u16,
    ) -> Self {
        Self::new_with_status(
            activation_id,
            interface,
            original_mac,
            randomized_mac,
            interface_was_up,
            tor_uid,
            tor_transport_port,
            tor_dns_port,
            UmbraStatus::Active,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_status(
        activation_id: String,
        interface: String,
        original_mac: String,
        randomized_mac: String,
        interface_was_up: bool,
        tor_uid: u32,
        tor_transport_port: u16,
        tor_dns_port: u16,
        status: UmbraStatus,
    ) -> Self {
        Self {
            version: 1,
            activation_id,
            status,
            interface,
            original_mac,
            randomized_mac,
            interface_was_up,
            tor_uid,
            tor_transport_port,
            tor_dns_port,
        }
    }

    /// Validates internal consistency of the state structure
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(UmbraError::RuntimeStateCorrupt(format!(
                "unsupported state version {}",
                self.version
            )));
        }
        match self.status {
            UmbraStatus::Starting | UmbraStatus::Active | UmbraStatus::RecoveryRequired => {}
            _ => {
                return Err(UmbraError::RuntimeStateCorrupt(format!(
                    "invalid lifecycle status in active state: {}",
                    self.status
                )));
            }
        }
        if self.activation_id.trim().is_empty() {
            return Err(UmbraError::RuntimeStateCorrupt(
                "empty activation_id".to_string(),
            ));
        }
        if self.interface.trim().is_empty() {
            return Err(UmbraError::RuntimeStateCorrupt(
                "empty interface name".to_string(),
            ));
        }
        let orig_mac = MacAddress::parse(&self.original_mac).map_err(|e| {
            UmbraError::RuntimeStateCorrupt(format!(
                "invalid original_mac '{}': {e}",
                self.original_mac
            ))
        })?;
        if orig_mac.is_all_zeros() {
            return Err(UmbraError::RuntimeStateCorrupt(
                "original_mac cannot be all zeros".to_string(),
            ));
        }
        let rand_mac = MacAddress::parse(&self.randomized_mac).map_err(|e| {
            UmbraError::RuntimeStateCorrupt(format!(
                "invalid randomized_mac '{}': {e}",
                self.randomized_mac
            ))
        })?;
        if rand_mac.is_all_zeros() {
            return Err(UmbraError::RuntimeStateCorrupt(
                "randomized_mac cannot be all zeros".to_string(),
            ));
        }
        if self.tor_transport_port == 0 || self.tor_dns_port == 0 {
            return Err(UmbraError::RuntimeStateCorrupt(
                "invalid zero port in state".to_string(),
            ));
        }
        Ok(())
    }

    /// Atomically persists state to /run/umbra/active.json with 0600 permissions
    pub fn save(&self) -> Result<()> {
        self.save_to_path(Path::new(RUNTIME_STATE_FILE))
    }

    pub fn save_to_path(&self, target_path: &Path) -> Result<()> {
        self.validate()?;

        if let Some(parent) = target_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(|e| {
                    UmbraError::RuntimeStateIo(format!(
                        "failed to create dir {}: {e}",
                        parent.display()
                    ))
                })?;
                let mut perms = fs::metadata(parent)
                    .map_err(|e| UmbraError::RuntimeStateIo(e.to_string()))?
                    .permissions();
                perms.set_mode(0o700);
                let _ = fs::set_permissions(parent, perms);
            }
        }

        let tmp_path = target_path.with_extension("tmp");
        let content = serde_json::to_vec_pretty(self)?;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| {
                UmbraError::RuntimeStateIo(format!("failed to open tmp state file: {e}"))
            })?;

        file.write_all(&content).map_err(|e| {
            UmbraError::RuntimeStateIo(format!("failed to write tmp state file: {e}"))
        })?;
        file.sync_all().map_err(|e| {
            UmbraError::RuntimeStateIo(format!("failed to sync tmp state file: {e}"))
        })?;
        drop(file);

        fs::rename(&tmp_path, target_path).map_err(|e| {
            UmbraError::RuntimeStateIo(format!("failed to atomically commit state file: {e}"))
        })?;

        Ok(())
    }

    /// Loads active state from /run/umbra/active.json
    pub fn load() -> Result<Option<Self>> {
        Self::load_from_path(Path::new(RUNTIME_STATE_FILE))
    }

    pub fn load_from_path(path: &Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }

        let mut file = File::open(path).map_err(|e| {
            UmbraError::RuntimeStateIo(format!("failed to open state file {}: {e}", path.display()))
        })?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)
            .map_err(|e| UmbraError::RuntimeStateIo(format!("failed to read state file: {e}")))?;

        let state: Self = serde_json::from_slice(&content)
            .map_err(|e| UmbraError::RuntimeStateCorrupt(format!("JSON parsing error: {e}")))?;

        state.validate()?;
        Ok(Some(state))
    }

    /// Safely removes active.json from /run/umbra
    pub fn remove() -> Result<()> {
        Self::remove_from_path(Path::new(RUNTIME_STATE_FILE))
    }

    pub fn remove_from_path(path: &Path) -> Result<()> {
        if path.exists() {
            fs::remove_file(path).map_err(|e| {
                UmbraError::RuntimeStateIo(format!("failed to remove state file: {e}"))
            })?;
        }
        Ok(())
    }
}
