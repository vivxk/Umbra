//! Explicit recovery and stop workflows restoring host to normal networking.

use crate::constants::{NFT_TABLE_FAMILY, NFT_TABLE_NAME};
use crate::error::Result;
use crate::firewall::FirewallController;
use crate::interface::{InterfaceBaseline, InterfaceController};
use crate::mac::MacAddress;
use crate::runtime_state::ActiveState;

pub struct RecoveryController;

impl RecoveryController {
    /// Executes clean explicit stop workflow from an active state
    pub fn stop() -> Result<()> {
        let state = match ActiveState::load()? {
            Some(s) => s,
            None => {
                // Check if orphaned firewall table exists
                if FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME)? {
                    FirewallController::authenticate_ownership(NFT_TABLE_FAMILY, NFT_TABLE_NAME)?;
                    FirewallController::teardown(NFT_TABLE_FAMILY, NFT_TABLE_NAME)?;
                }
                return Ok(());
            }
        };

        // 1. Teardown Firewall
        FirewallController::teardown(NFT_TABLE_FAMILY, NFT_TABLE_NAME)?;

        // 2. Restore Interface Baseline
        let orig_mac = MacAddress::parse(&state.original_mac)?;
        let baseline = InterfaceBaseline {
            name: state.interface.clone(),
            original_mac: orig_mac,
            was_up: state.interface_was_up,
        };

        InterfaceController::restore_baseline(&baseline)?;

        // 3. Remove runtime state
        ActiveState::remove()?;

        Ok(())
    }

    /// Performs full explicit recovery returning host to normal networking
    pub fn recover_normal() -> Result<Vec<String>> {
        let mut actions = Vec::new();
        let loaded_state = ActiveState::load()?;

        // 1. Reconcile Firewall
        let table_present = FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME)?;
        if table_present {
            // Strictly authenticate before removal
            FirewallController::authenticate_ownership(NFT_TABLE_FAMILY, NFT_TABLE_NAME)?;
            FirewallController::teardown(NFT_TABLE_FAMILY, NFT_TABLE_NAME)?;
            actions.push("Successfully removed Umbra firewall table".to_string());
        } else {
            actions.push("Firewall table inet umbra was not present".to_string());
        }

        // 2. Reconcile Interface / MAC
        if let Some(state) = loaded_state {
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
            }

            let _ = ActiveState::remove();
            actions.push("Cleared runtime state active.json".to_string());
        } else {
            actions.push("No active runtime state file found to restore MAC".to_string());
        }

        Ok(actions)
    }
}
