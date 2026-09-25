//! Live system state verification and health reporting.

use crate::constants::{
    DEFAULT_TOR_CONTROLPORT, DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT, NFT_TABLE_FAMILY,
    NFT_TABLE_NAME,
};
use crate::error::Result;
use crate::firewall::FirewallController;
use crate::interface::InterfaceController;
use crate::runtime_state::{ActiveState, UmbraStatus};
use crate::tor::TorController;

#[derive(Debug, Clone)]
pub struct VerificationReport {
    pub status: UmbraStatus,
    pub firewall_ok: bool,
    pub tor_process_ok: bool,
    pub transport_ok: bool,
    pub dnsport_ok: bool,
    pub controlport_ok: bool,
    pub interface: Option<String>,
    pub live_mac: Option<String>,
    pub mac_matches_state: bool,
    pub details: Vec<String>,
}

pub struct LiveVerifier;

impl LiveVerifier {
    /// Conducts a comprehensive live verification against the actual kernel and processes
    pub fn verify_current_state() -> Result<VerificationReport> {
        let (active_state, corrupt_state_err) = match ActiveState::load() {
            Ok(s) => (s, None),
            Err(e) => (None, Some(e)),
        };

        let mut details = Vec::new();
        let mut firewall_ok = false;
        let mut tor_process_ok = false;
        let mut transport_ok = false;
        let mut dnsport_ok = false;
        let mut mac_matches_state = false;
        let mut live_mac_str = None;
        let mut interface_name = None;
        let mut inspection_error = false;

        if let Some(ref e) = corrupt_state_err {
            details.push(format!(
                "state: runtime state file is unreadable or corrupt: {e}"
            ));
        }

        // 1. Check Firewall
        let table_exists = match FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME)
        {
            Ok(exists) => exists,
            Err(e) => {
                details.push(format!("nftables: inspection error: {e}"));
                inspection_error = true;
                false
            }
        };

        if table_exists {
            let act_id = active_state.as_ref().map(|s| s.activation_id.as_str());
            match FirewallController::authenticate_ownership_with_id(
                NFT_TABLE_FAMILY,
                NFT_TABLE_NAME,
                act_id,
            ) {
                Ok(_) => {
                    if let Some(ref state) = active_state {
                        let fw_config = crate::firewall::FirewallConfig {
                            table_name: NFT_TABLE_NAME.to_string(),
                            table_family: NFT_TABLE_FAMILY.to_string(),
                            tor_uid: state.tor_uid,
                            tor_transport_port: state.tor_transport_port,
                            tor_dns_port: state.tor_dns_port,
                            egress_interface: state.interface.clone(),
                            activation_id: state.activation_id.clone(),
                            ..Default::default()
                        };
                        match FirewallController::verify_live(&fw_config) {
                            Ok(_) => {
                                firewall_ok = true;
                                details.push(
                                    "nftables: verified table inet umbra with ownership marker and all enforcement policies"
                                        .to_string(),
                                );
                            }
                            Err(e) => {
                                details.push(format!("nftables: policy verification failed: {e}"));
                            }
                        }
                    } else {
                        firewall_ok = true;
                        details.push(
                            "nftables: verified table inet umbra with ownership marker".to_string(),
                        );
                    }
                }
                Err(e) => {
                    details.push(format!(
                        "nftables: table exists but ownership check failed: {e}"
                    ));
                }
            }
        } else {
            details.push("nftables: table inet umbra is absent".to_string());
        }

        // 2. Check Tor process
        let mut verified_tor_ident = None;
        match TorController::find_tor_process() {
            Ok(Some(ident)) => {
                tor_process_ok = true;
                details.push(format!(
                    "tor: verified running process PID {} (UID {}, exe: {})",
                    ident.pid, ident.uid, ident.exe_path
                ));
                verified_tor_ident = Some(ident);
            }
            Ok(None) => {
                details.push("tor: no running tor process detected in /proc".to_string());
            }
            Err(e) => {
                details.push(format!("tor: inspection error: {e}"));
                inspection_error = true;
            }
        }

        // 3. Check Tor TransPort
        let transport_port = active_state
            .as_ref()
            .map(|s| s.tor_transport_port)
            .unwrap_or(DEFAULT_TOR_TRANSPORT);
        match TorController::verify_transport_with_identity(
            transport_port,
            verified_tor_ident.as_ref(),
        ) {
            Ok(_) => {
                transport_ok = true;
                details.push(format!(
                    "tor: TransPort 127.0.0.1:{transport_port} is responding and verified"
                ));
            }
            Err(crate::error::UmbraError::TorInspectionError(e)) => {
                details.push(format!("tor: TransPort inspection error: {e}"));
                inspection_error = true;
            }
            Err(e) => {
                details.push(format!(
                    "tor: TransPort 127.0.0.1:{transport_port} failed: {e}"
                ));
            }
        }

        // 4. Check Tor DNSPort
        let dns_port = active_state
            .as_ref()
            .map(|s| s.tor_dns_port)
            .unwrap_or(DEFAULT_TOR_DNSPORT);
        match TorController::verify_dnsport_with_identity(dns_port, verified_tor_ident.as_ref()) {
            Ok(_) => {
                dnsport_ok = true;
                details.push(format!(
                    "tor: DNSPort 127.0.0.1:{dns_port} is responding and verified"
                ));
            }
            Err(crate::error::UmbraError::TorInspectionError(e)) => {
                details.push(format!("tor: DNSPort inspection error: {e}"));
                inspection_error = true;
            }
            Err(e) => {
                details.push(format!("tor: DNSPort 127.0.0.1:{dns_port} failed: {e}"));
            }
        }

        // 5. Check Tor ControlPort (local-only, Tor protocol)
        let mut controlport_ok = false;
        let control_port = DEFAULT_TOR_CONTROLPORT;
        match TorController::verify_controlport_with_identity(
            control_port,
            verified_tor_ident.as_ref(),
        ) {
            Ok(_) => {
                controlport_ok = true;
                details.push(format!(
                    "tor: ControlPort 127.0.0.1:{control_port} is responding and verified"
                ));
            }
            Err(crate::error::UmbraError::TorInspectionError(e)) => {
                details.push(format!("tor: ControlPort inspection error: {e}"));
                inspection_error = true;
            }
            Err(e) => {
                details.push(format!("tor: ControlPort 127.0.0.1:{control_port}: {e}"));
            }
        }

        // 6. Check Interface & MAC
        if let Some(ref state) = active_state {
            interface_name = Some(state.interface.clone());
            if let Ok(current_mac) = InterfaceController::read_mac(&state.interface) {
                live_mac_str = Some(current_mac.to_string());
                if current_mac.to_string().to_lowercase() == state.randomized_mac.to_lowercase() {
                    mac_matches_state = true;
                    details.push(format!(
                        "mac: interface {} has expected randomized MAC {}",
                        state.interface, current_mac
                    ));
                } else {
                    details.push(format!(
                        "mac: interface {} MAC mismatch (live: {}, expected: {})",
                        state.interface, current_mac, state.randomized_mac
                    ));
                }
            }
        }

        // 7. Safe inspection of /etc/resolv.conf diagnostics
        if let Ok(resolv) = crate::dns::DnsController::inspect_resolv_conf() {
            if !resolv.nameservers.is_empty() {
                details.push(format!(
                    "dns: /etc/resolv.conf nameservers: {} (loopback-only: {})",
                    resolv.nameservers.join(", "),
                    resolv.loopback_only
                ));
            }
            for warning in &resolv.warnings {
                details.push(format!("dns: [warning] {warning}"));
            }
        }

        // Determine aggregated status (Section 9: ACTIVE requires MAC integrity and full component health)
        let status = if corrupt_state_err.is_some() {
            UmbraStatus::RecoveryRequired
        } else if let Some(ref state) = active_state {
            if state.status == UmbraStatus::Starting {
                UmbraStatus::Starting
            } else if state.status == UmbraStatus::RecoveryRequired {
                UmbraStatus::RecoveryRequired
            } else if inspection_error {
                UmbraStatus::Unknown
            } else if firewall_ok && tor_process_ok && transport_ok && dnsport_ok {
                if mac_matches_state {
                    UmbraStatus::Active
                } else if live_mac_str.is_none() {
                    UmbraStatus::Unknown
                } else {
                    UmbraStatus::RecoveryRequired
                }
            } else {
                UmbraStatus::RecoveryRequired
            }
        } else if !table_exists {
            UmbraStatus::Inactive
        } else if inspection_error {
            UmbraStatus::Unknown
        } else {
            // No runtime state, but firewall table exists!
            UmbraStatus::RecoveryRequired
        };

        Ok(VerificationReport {
            status,
            firewall_ok,
            tor_process_ok,
            transport_ok,
            dnsport_ok,
            controlport_ok,
            interface: interface_name,
            live_mac: live_mac_str,
            mac_matches_state,
            details,
        })
    }
}
