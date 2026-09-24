//! Atomic startup transaction engine enforcing fail-closed lifecycle invariants.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{
    DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT, NFT_TABLE_FAMILY, NFT_TABLE_NAME,
    RUNTIME_STATE_FILE,
};
use crate::error::{Result, UmbraError};
use crate::firewall::{FirewallConfig, FirewallController};
use crate::interface::{InterfaceBaseline, InterfaceController};
use crate::mac::MacAddress;
use crate::runtime_state::{ActiveState, UmbraStatus};
use crate::tor::{TorController, TorIdentity};
use crate::verify::LiveVerifier;

/// Configuration options for the startup transaction
#[derive(Debug, Clone)]
pub struct StartupTransactionOptions {
    pub interface_override: Option<String>,
    pub transport_port: u16,
    pub dns_port: u16,
    pub state_file_override: Option<String>,
}

impl Default for StartupTransactionOptions {
    fn default() -> Self {
        Self {
            interface_override: None,
            transport_port: DEFAULT_TOR_TRANSPORT,
            dns_port: DEFAULT_TOR_DNSPORT,
            state_file_override: None,
        }
    }
}

/// Result returned upon successful execution of the startup transaction
#[derive(Debug, Clone)]
pub struct StartupTransactionResult {
    pub activation_id: String,
    pub interface: String,
    pub original_mac: MacAddress,
    pub randomized_mac: MacAddress,
    pub tor_identity: TorIdentity,
    pub transport_port: u16,
    pub dns_port: u16,
}

/// Transactional coordinator executing startup stages with fail-closed rollback
pub struct StartupTransaction;

impl StartupTransaction {
    /// Executes the full atomic startup transaction per Sections 30 & 31
    pub fn execute(options: StartupTransactionOptions) -> Result<StartupTransactionResult> {
        let state_path = options
            .state_file_override
            .as_deref()
            .map(Path::new)
            .unwrap_or_else(|| Path::new(RUNTIME_STATE_FILE));

        // 1. Guard against double-start / active session collision (Sections 26 & 48)
        if let Some(existing) = ActiveState::load_from_path(state_path)? {
            return Err(UmbraError::AlreadyActive {
                interface: existing.interface,
                activation_id: existing.activation_id,
            });
        }

        // Verify no orphan table exists in the kernel
        if FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME)? {
            return Err(UmbraError::FirewallOwnershipUnknown(
                "table inet umbra is already present in kernel without an active session file; explicit recovery is required"
                    .to_string(),
            ));
        }

        // 2. Pre-flight Tor Verification (Sections 15, 33, 34)
        // Verified BEFORE any host link/firewall mutations occur.
        let tor_ident = TorController::find_tor_process()?.ok_or(UmbraError::TorNotRunning)?;
        TorController::verify_transport_with_identity(options.transport_port, Some(&tor_ident))?;
        TorController::verify_dnsport_with_identity(options.dns_port, Some(&tor_ident))?;
        let tor_uid = tor_ident.uid;

        // 3. Egress Interface Resolution (Section 93)
        let iface = match options.interface_override {
            Some(name) => name,
            None => InterfaceController::detect_default_egress()?,
        };

        // 4. Capture Interface Baseline (Sections 26 & 28)
        let baseline = InterfaceController::capture_baseline(&iface)?;

        // 5. Generate and Apply Randomized MAC (Sections 24 & 25)
        // 5. Generate Activation ID and Firefall Configuration
        let activation_id = format!(
            "{:x}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );

        let fw_config = FirewallConfig {
            table_name: NFT_TABLE_NAME.to_string(),
            table_family: NFT_TABLE_FAMILY.to_string(),
            tor_uid,
            tor_transport_port: options.transport_port,
            tor_dns_port: options.dns_port,
            egress_interface: iface.clone(),
            activation_id: activation_id.clone(),
            ..Default::default()
        };

        // 6. Generate Randomized MAC
        let random_mac = MacAddress::generate_random()?;
        let mut mac_randomized = false;
        let mut firewall_installed = false;

        // 7. Persist STARTING / recoverable runtime state BEFORE any host mutation (Section 4)
        let mut active_state = ActiveState::new_with_status(
            activation_id.clone(),
            iface.clone(),
            baseline.original_mac.to_string(),
            random_mac.to_string(),
            baseline.was_up,
            tor_uid,
            options.transport_port,
            options.dns_port,
            fw_config.table_name.clone(),
            UmbraStatus::Starting,
        );
        active_state.save_to_path(state_path)?;

        // Execution with transactional rollback protection
        let result: Result<StartupTransactionResult> = (|| {
            // Atomically install restrictive firewall policy first (Section 31: restrictive before application traffic)
            FirewallController::install(&fw_config)?;
            firewall_installed = true;

            // Apply randomized MAC
            InterfaceController::apply_mac(&iface, random_mac)?;
            mac_randomized = true;

            // Post-activation live verification gate (Sections 32, 45, 77)
            let report = LiveVerifier::verify_current_state()?;
            if report.status != UmbraStatus::Active {
                return Err(UmbraError::FirewallVerificationFailed(format!(
                    "post-activation verification failed (status: {}): {:?}",
                    report.status, report.details
                )));
            }

            // Mark state as ACTIVE only after full live verification passes
            active_state.status = UmbraStatus::Active;
            active_state.save_to_path(state_path)?;

            Ok(StartupTransactionResult {
                activation_id,
                interface: iface.clone(),
                original_mac: baseline.original_mac,
                randomized_mac: random_mac,
                tor_identity: tor_ident,
                transport_port: options.transport_port,
                dns_port: options.dns_port,
            })
        })();

        match result {
            Ok(success) => Ok(success),
            Err(e) => {
                // Fail-Closed Rollback Engine (Sections 30, 47, 81)
                Self::rollback(
                    &baseline,
                    &fw_config,
                    mac_randomized,
                    firewall_installed,
                    state_path,
                    &mut active_state,
                )?;
                Err(e)
            }
        }
    }

    /// Executes safe rollback without ever opening direct internet fallback
    fn rollback(
        baseline: &InterfaceBaseline,
        fw_config: &FirewallConfig,
        mac_randomized: bool,
        firewall_installed: bool,
        state_path: &Path,
        active_state: &mut ActiveState,
    ) -> Result<()> {
        let mut rollback_errors = Vec::new();

        // 1. Teardown firewall if installed
        if firewall_installed {
            if let Err(e) = FirewallController::teardown_with_id(
                &fw_config.table_family,
                &fw_config.table_name,
                Some(&fw_config.activation_id),
            ) {
                rollback_errors.push(format!("failed to teardown firewall: {e}"));
            }
        }

        // 2. Revert MAC if randomized
        if mac_randomized {
            if let Err(e) = InterfaceController::restore_baseline(baseline) {
                rollback_errors.push(format!("failed to restore baseline MAC: {e}"));
            }
        }

        if !rollback_errors.is_empty() {
            // Section 5: If rollback cannot restore baseline, preserve recovery state!
            active_state.status = UmbraStatus::RecoveryRequired;
            let _ = active_state.save_to_path(state_path);

            return Err(UmbraError::RecoveryUncertain(format!(
                "startup failed and rollback encountered errors (recovery state preserved, network remains fail-closed): {}",
                rollback_errors.join("; ")
            )));
        }

        // 3. Remove state file ONLY if rollback succeeded cleanly
        let _ = ActiveState::remove_from_path(state_path);

        Ok(())
    }
}
