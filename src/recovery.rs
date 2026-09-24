//! Explicit recovery and stop workflows restoring host to normal networking.

use std::path::Path;

use crate::constants::{LOCK_FILE, NFT_TABLE_FAMILY, NFT_TABLE_NAME, RUNTIME_STATE_FILE};
use crate::error::{Result, UmbraError};
use crate::firewall::FirewallController;
use crate::interface::{InterfaceBaseline, InterfaceController};
use crate::mac::MacAddress;
use crate::runtime_state::ActiveState;
use crate::system::ProcessLock;

/// Configuration options for stop and recovery workflows
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOptions {
    pub state_file_override: Option<String>,
    pub lock_file_override: Option<String>,
    pub table_family: String,
    pub table_name: String,
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            state_file_override: None,
            lock_file_override: None,
            table_family: NFT_TABLE_FAMILY.to_string(),
            table_name: NFT_TABLE_NAME.to_string(),
        }
    }
}

impl RecoveryOptions {
    pub fn resolved_lock_path(&self) -> std::path::PathBuf {
        if let Some(ref lock_path) = self.lock_file_override {
            std::path::PathBuf::from(lock_path)
        } else if let Some(ref state_path) = self.state_file_override {
            let p = std::path::Path::new(state_path);
            p.with_extension("lock")
        } else {
            std::path::PathBuf::from(LOCK_FILE)
        }
    }
}

/// Extracts a string field from a JSON string without full deserialization
pub fn extract_json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{field}\"");
    let key_pos = json.find(&key)?;
    let after_key = &json[key_pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let after_colon = after_key[colon_pos + 1..].trim_start();
    if let Some(after_quote) = after_colon.strip_prefix('"') {
        let end_quote = after_quote.find('"')?;
        Some(after_quote[..end_quote].to_string())
    } else {
        None
    }
}

/// Attempts best-effort extraction of interface baseline from a corrupt state file
fn try_salvage_baseline_from_corrupt_file(path: &Path) -> Option<InterfaceBaseline> {
    let content = std::fs::read_to_string(path).ok()?;
    let iface = extract_json_field(&content, "interface")?;
    if iface.trim().is_empty() || iface == "lo" {
        return None;
    }
    let mac_str = extract_json_field(&content, "original_mac")?;
    let orig_mac = MacAddress::parse(&mac_str).ok()?;
    if orig_mac.is_all_zeros() {
        return None;
    }
    if !Path::new("/sys/class/net").join(&iface).exists() {
        return None;
    }
    let was_up = InterfaceController::is_administratively_up(&iface).unwrap_or(true);
    Some(InterfaceBaseline {
        name: iface,
        original_mac: orig_mac,
        was_up,
    })
}

pub struct RecoveryController;

impl RecoveryController {
    /// Executes clean explicit stop workflow from an active state using default system paths
    pub fn stop() -> Result<()> {
        Self::stop_with_options(&RecoveryOptions::default())
    }

    /// Executes clean explicit stop workflow with custom options
    pub fn stop_with_options(options: &RecoveryOptions) -> Result<()> {
        let lock_path = options.resolved_lock_path();
        let lock = ProcessLock::acquire_path(&lock_path)?;

        let state_path = options
            .state_file_override
            .as_deref()
            .map(Path::new)
            .unwrap_or_else(|| Path::new(RUNTIME_STATE_FILE));

        let state = match ActiveState::load_from_path(state_path)? {
            Some(s) => s,
            None => {
                // If runtime state is absent, check whether an orphaned table exists
                if FirewallController::table_exists(&options.table_family, &options.table_name)? {
                    return Err(UmbraError::RecoveryUncertain(
                        "Cannot cleanly stop: runtime state file is absent but firewall table exists. Interface baseline MAC cannot be restored. Use 'umbra recover --force' to force recovery."
                            .to_string(),
                    ));
                }
                drop(lock);
                let _ = ProcessLock::cleanup_path(&lock_path);
                return Ok(());
            }
        };

        // 1. Teardown Firewall with strict ownership authentication
        FirewallController::teardown(&options.table_family, &options.table_name)?;

        // 2. Restore Interface Baseline (MAC and administrative UP/DOWN state)
        let orig_mac = MacAddress::parse(&state.original_mac)?;
        let baseline = InterfaceBaseline {
            name: state.interface.clone(),
            original_mac: orig_mac,
            was_up: state.interface_was_up,
        };

        InterfaceController::restore_baseline(&baseline)?;

        // 3. Remove runtime state file only after restoration verification succeeds
        ActiveState::remove_from_path(state_path)?;

        // 4. Release lock, then clean lock file
        drop(lock);
        let _ = ProcessLock::cleanup_path(&lock_path);

        Ok(())
    }

    /// Convenience wrapper for stop using a custom state file path
    pub fn stop_with_state_path(state_path: &Path) -> Result<()> {
        Self::stop_with_options(&RecoveryOptions {
            state_file_override: Some(state_path.to_string_lossy().to_string()),
            ..Default::default()
        })
    }

    /// Performs normal explicit recovery returning host to normal networking
    pub fn recover_normal() -> Result<Vec<String>> {
        Self::recover_normal_with_options(&RecoveryOptions::default())
    }

    /// Performs normal explicit recovery with custom options
    pub fn recover_normal_with_options(options: &RecoveryOptions) -> Result<Vec<String>> {
        let lock_path = options.resolved_lock_path();
        let lock = ProcessLock::acquire_path(&lock_path)?;

        let mut actions = Vec::new();
        let state_path = options
            .state_file_override
            .as_deref()
            .map(Path::new)
            .unwrap_or_else(|| Path::new(RUNTIME_STATE_FILE));

        // Load active state. If state file is corrupt, normal recovery halts to prevent uncertain actions
        let loaded_state = match ActiveState::load_from_path(state_path) {
            Ok(s) => s,
            Err(e) => {
                return Err(UmbraError::RecoveryUncertain(format!(
                    "Runtime state file is corrupt or unreadable: {e}. Normal recovery cannot safely determine baseline MAC. Use 'umbra recover --force' to force recovery."
                )));
            }
        };

        // 1. Reconcile Firewall
        let table_present =
            FirewallController::table_exists(&options.table_family, &options.table_name)?;
        if table_present {
            // Strictly authenticate before removal
            FirewallController::authenticate_ownership(&options.table_family, &options.table_name)?;
            FirewallController::teardown(&options.table_family, &options.table_name)?;
            actions.push(format!(
                "Successfully authenticated and removed Umbra firewall table {} {}",
                options.table_family, options.table_name
            ));
        } else {
            actions.push(format!(
                "Firewall table {} {} was not present",
                options.table_family, options.table_name
            ));
        }

        // 2. Reconcile Interface / MAC
        if let Some(state) = loaded_state {
            let orig_mac = MacAddress::parse(&state.original_mac).map_err(|e| {
                UmbraError::RecoveryUncertain(format!(
                    "Invalid original MAC recorded in state ({}): {e}. Use 'umbra recover --force' to force recovery.",
                    state.original_mac
                ))
            })?;

            let baseline = InterfaceBaseline {
                name: state.interface.clone(),
                original_mac: orig_mac,
                was_up: state.interface_was_up,
            };

            // Restoring baseline MUST NOT swallow errors
            InterfaceController::restore_baseline(&baseline)?;
            actions.push(format!(
                "Restored interface {} to original MAC {}",
                state.interface, state.original_mac
            ));

            // Only remove state file AFTER successful interface restoration
            ActiveState::remove_from_path(state_path)?;
            actions.push(format!(
                "Cleared runtime state file {}",
                state_path.display()
            ));
        } else {
            actions.push("No active runtime state file found to restore MAC".to_string());
        }

        // 3. Release lock and clean lock file
        drop(lock);
        let _ = ProcessLock::cleanup_path(&lock_path);
        actions.push("Cleaned lock file".to_string());

        Ok(actions)
    }

    /// Convenience wrapper for normal recovery with custom state path
    pub fn recover_normal_with_state_path(state_path: &Path) -> Result<Vec<String>> {
        Self::recover_normal_with_options(&RecoveryOptions {
            state_file_override: Some(state_path.to_string_lossy().to_string()),
            ..Default::default()
        })
    }

    /// Performs force recovery when state file is missing, corrupt, or unreadable.
    /// Inspects system for table inet umbra, verifies ownership marker (umbra-managed),
    /// deletes the table if verified. If table lacks verified marker, refuses to touch it.
    pub fn recover_force() -> Result<Vec<String>> {
        Self::recover_force_with_options(&RecoveryOptions::default())
    }

    /// Performs force recovery with custom options
    pub fn recover_force_with_options(options: &RecoveryOptions) -> Result<Vec<String>> {
        let lock_path = options.resolved_lock_path();
        let lock = ProcessLock::acquire_path(&lock_path)?;

        let mut actions = Vec::new();
        let state_path = options
            .state_file_override
            .as_deref()
            .map(Path::new)
            .unwrap_or_else(|| Path::new(RUNTIME_STATE_FILE));

        // 1. Inspect and Reconcile Firewall
        let table_present =
            FirewallController::table_exists(&options.table_family, &options.table_name)?;
        if table_present {
            // Strictly authenticate ownership marker (umbra-managed) before touching
            match FirewallController::authenticate_ownership(
                &options.table_family,
                &options.table_name,
            ) {
                Ok(_) => {
                    FirewallController::teardown(&options.table_family, &options.table_name)?;
                    actions.push(format!(
                        "Successfully authenticated ownership marker and removed firewall table {} {}",
                        options.table_family, options.table_name
                    ));
                }
                Err(e) => {
                    return Err(UmbraError::FirewallOwnershipUnknown(format!(
                        "Refusing force recovery: table {} {} exists but lacks verified ownership marker: {e}. Network remains fail-closed.",
                        options.table_family, options.table_name
                    )));
                }
            }
        } else {
            actions.push(format!(
                "Firewall table {} {} was not present",
                options.table_family, options.table_name
            ));
        }

        // 2. Best-effort interface / MAC restoration
        let loaded_state = ActiveState::load_from_path(state_path);
        match loaded_state {
            Ok(Some(state)) => {
                // State was readable despite force mode
                if let Ok(orig_mac) = MacAddress::parse(&state.original_mac) {
                    let baseline = InterfaceBaseline {
                        name: state.interface.clone(),
                        original_mac: orig_mac,
                        was_up: state.interface_was_up,
                    };
                    match InterfaceController::restore_baseline(&baseline) {
                        Ok(_) => actions.push(format!(
                            "Restored interface {} to original MAC {}",
                            state.interface, state.original_mac
                        )),
                        Err(e) => actions.push(format!(
                            "Warning: failed to restore interface {}: {e}",
                            state.interface
                        )),
                    }
                } else {
                    actions.push(format!(
                        "Warning: state file had unparseable MAC '{}'; hardware MAC not restored",
                        state.original_mac
                    ));
                }
            }
            Ok(None) => {
                actions.push(
                    "Warning: runtime state file was absent; baseline MAC unknown, interface MAC not restored. Please verify network manager or re-plug interface if MAC was changed."
                        .to_string(),
                );
            }
            Err(e) => {
                // Best-effort: attempt to salvage baseline from corrupt state file
                if let Some(salvaged) = try_salvage_baseline_from_corrupt_file(state_path) {
                    match InterfaceController::restore_baseline(&salvaged) {
                        Ok(_) => actions.push(format!(
                            "Best-effort restoration: salvaged baseline from corrupt state file and restored interface {} to original MAC {}",
                            salvaged.name, salvaged.original_mac
                        )),
                        Err(err) => actions.push(format!(
                            "Warning: salvaged baseline for interface {} from corrupt state file, but restoration failed: {err}",
                            salvaged.name
                        )),
                    }
                } else {
                    actions.push(format!(
                        "Warning: runtime state file was corrupt ({e}); baseline MAC could not be salvaged or restored. Please verify network manager or re-plug interface if MAC was changed."
                    ));
                }
            }
        }

        // 3. Remove corrupt or existing state file
        if state_path.exists() {
            let _ = ActiveState::remove_from_path(state_path);
            actions.push(format!(
                "Cleaned runtime state file {}",
                state_path.display()
            ));
        }

        // 4. Release lock, then clean lock file
        drop(lock);
        let _ = ProcessLock::cleanup_path(&lock_path);
        actions.push("Cleaned lock file".to_string());

        Ok(actions)
    }

    /// Convenience wrapper for force recovery with custom state path
    pub fn recover_force_with_state_path(state_path: &Path) -> Result<Vec<String>> {
        Self::recover_force_with_options(&RecoveryOptions {
            state_file_override: Some(state_path.to_string_lossy().to_string()),
            ..Default::default()
        })
    }
}
