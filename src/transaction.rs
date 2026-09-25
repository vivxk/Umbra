//! Atomic startup transaction engine enforcing fail-closed lifecycle invariants.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::constants::{
    DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT, NFT_TABLE_FAMILY, NFT_TABLE_NAME,
    RUNTIME_STATE_FILE,
};
use crate::dns::DnsController;
use crate::error::{Result, UmbraError};
use crate::firewall::{FirewallConfig, FirewallController};
use crate::interface::{InterfaceBaseline, InterfaceController};
use crate::mac::MacAddress;
use crate::runtime_state::{ActiveState, UmbraStatus};
use crate::tor::TorController;
use crate::verify::LiveVerifier;

/// Configuration options for the startup transaction
#[derive(Debug, Clone)]
pub struct StartupTransactionOptions {
    pub interface_override: Option<String>,
    pub transport_port: u16,
    pub dns_port: u16,
    pub state_file_override: Option<String>,
    pub lock_file_override: Option<String>,
    pub no_mac_randomize: bool,
}

impl Default for StartupTransactionOptions {
    fn default() -> Self {
        Self {
            interface_override: None,
            transport_port: DEFAULT_TOR_TRANSPORT,
            dns_port: DEFAULT_TOR_DNSPORT,
            state_file_override: None,
            lock_file_override: None,
            no_mac_randomize: false,
        }
    }
}

impl StartupTransactionOptions {
    pub fn resolved_lock_path(&self) -> std::path::PathBuf {
        if let Some(ref lock_path) = self.lock_file_override {
            std::path::PathBuf::from(lock_path)
        } else if let Some(ref state_path) = self.state_file_override {
            let p = std::path::Path::new(state_path);
            p.with_extension("lock")
        } else {
            std::path::PathBuf::from(crate::constants::LOCK_FILE)
        }
    }
}

/// Result returned upon successful execution of the startup transaction
#[derive(Debug, Clone)]
pub struct StartupTransactionResult {
    pub interface: String,
    pub original_mac: MacAddress,
    pub randomized_mac: MacAddress,
    pub transport_port: u16,
    pub dns_port: u16,
}

/// Transactional coordinator executing startup stages with fail-closed rollback
pub struct StartupTransaction;

impl StartupTransaction {
    /// Executes the full atomic startup transaction, establishing fail-closed routing and verifying the boundary
    pub fn execute(options: StartupTransactionOptions) -> Result<StartupTransactionResult> {
        let lock_path = options.resolved_lock_path();
        let _lock = crate::system::ProcessLock::acquire_path(&lock_path)?;

        let state_path = options
            .state_file_override
            .as_deref()
            .map(Path::new)
            .unwrap_or_else(|| Path::new(RUNTIME_STATE_FILE));

        // 1. Guard against double-start or active session collision
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

        // 2. Pre-flight Tor Verification: listeners must be running and owned by Tor
        // Verified before any host link/firewall mutations occur.
        let tor_ident = TorController::find_tor_process()?.ok_or(UmbraError::TorNotRunning)?;
        TorController::verify_transport_with_identity(options.transport_port, Some(&tor_ident))?;
        TorController::verify_dnsport_with_identity(options.dns_port, Some(&tor_ident))?;
        DnsController::verify_local_resolution(options.dns_port)?;
        let tor_uid = tor_ident.uid;

        // 3. Egress Interface Resolution
        let iface = match options.interface_override {
            Some(name) => name,
            None => InterfaceController::detect_default_egress()?,
        };

        // 4. Capture Interface Baseline (original MAC and link state)
        let baseline = InterfaceController::capture_baseline(&iface)?;

        // 5. Generate unique activation ID and firewall configuration
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
            activation_id: activation_id.clone(),
        };

        // 6. Generate or Preserve MAC
        let random_mac = if options.no_mac_randomize {
            baseline.original_mac
        } else {
            MacAddress::generate_random()?
        };
        let mut mac_randomized = false;
        let mut firewall_installed = false;

        // 7. Persist STARTING / recoverable runtime state BEFORE any host mutation
        let mut active_state = ActiveState::new_with_status(
            activation_id,
            iface.clone(),
            baseline.original_mac.to_string(),
            random_mac.to_string(),
            baseline.was_up,
            tor_uid,
            options.transport_port,
            options.dns_port,
            UmbraStatus::Starting,
        );
        active_state.save_to_path(state_path)?;

        // Execution with transactional rollback protection
        let result: Result<StartupTransactionResult> = (|| {
            // Atomically install restrictive firewall policy first (restrictive before application traffic)
            FirewallController::install(&fw_config)?;
            firewall_installed = true;

            // Apply randomized MAC if enabled
            if !options.no_mac_randomize {
                InterfaceController::apply_mac(&iface, random_mac)?;
                mac_randomized = true;
            }

            // Post-activation live verification gate: ensure firewall, Tor, and interfaces are fully healthy
            let verify_opts = crate::verify::VerifyOptions {
                state_file_override: options.state_file_override.clone(),
                ..Default::default()
            };
            let report = LiveVerifier::verify_with_options(&verify_opts)?;
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
                interface: iface.clone(),
                original_mac: baseline.original_mac,
                randomized_mac: random_mac,
                transport_port: options.transport_port,
                dns_port: options.dns_port,
            })
        })();

        match result {
            Ok(success) => Ok(success),
            Err(e) => {
                // Fail-Closed Rollback: safely restore baseline state or fail closed
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
    pub fn rollback(
        baseline: &InterfaceBaseline,
        fw_config: &FirewallConfig,
        mac_randomized: bool,
        firewall_installed: bool,
        state_path: &Path,
        active_state: &mut ActiveState,
    ) -> Result<()> {
        let mut rollback_errors = Vec::new();

        // 1. Revert MAC FIRST if randomized, keeping fail-closed firewall active
        if mac_randomized {
            if let Err(e) = InterfaceController::restore_baseline(baseline) {
                rollback_errors.push(format!("failed to restore baseline MAC: {e}"));
            }
        }

        // 2. Teardown firewall ONLY if MAC restoration succeeded (or MAC was never randomized)
        if firewall_installed && rollback_errors.is_empty() {
            if let Err(e) = FirewallController::teardown_with_id(
                &fw_config.table_family,
                &fw_config.table_name,
                Some(&fw_config.activation_id),
            ) {
                rollback_errors.push(format!("failed to teardown firewall: {e}"));
            }
        }

        if !rollback_errors.is_empty() {
            // Invariant: if rollback cannot restore baseline, preserve recovery state!
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
