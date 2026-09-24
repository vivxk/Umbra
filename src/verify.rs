//! Live system state verification and health reporting.

use crate::constants::{
    DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT, NFT_TABLE_FAMILY, NFT_TABLE_NAME,
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
    pub interface: Option<String>,
    pub live_mac: Option<String>,
    pub mac_matches_state: bool,
    pub details: Vec<String>,
}

pub struct LiveVerifier;

impl LiveVerifier {
    /// Conducts a comprehensive live verification against the actual kernel and processes
    pub fn verify_current_state() -> Result<VerificationReport> {
        let active_state = ActiveState::load()?;

        let mut details = Vec::new();
        let mut firewall_ok = false;
        let mut tor_process_ok = false;
        let mut transport_ok = false;
        let mut dnsport_ok = false;
        let mut mac_matches_state = false;
        let mut live_mac_str = None;
        let mut interface_name = None;

        // 1. Check Firewall
        let table_exists = FirewallController::table_exists(NFT_TABLE_FAMILY, NFT_TABLE_NAME)?;
        if table_exists {
            match FirewallController::authenticate_ownership(NFT_TABLE_FAMILY, NFT_TABLE_NAME) {
                Ok(_) => {
                    firewall_ok = true;
                    details.push(
                        "nftables: verified table inet umbra with ownership marker".to_string(),
                    );
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
        match TorController::find_tor_process() {
            Ok(Some(ident)) => {
                tor_process_ok = true;
                details.push(format!(
                    "tor: verified running process PID {} (UID {}, exe: {})",
                    ident.pid, ident.uid, ident.exe_path
                ));
            }
            Ok(None) => {
                details.push("tor: no running tor process detected in /proc".to_string());
            }
            Err(e) => {
                details.push(format!("tor: inspection error: {e}"));
            }
        }

        // 3. Check Tor TransPort
        let transport_port = active_state
            .as_ref()
            .map(|s| s.tor_transport_port)
            .unwrap_or(DEFAULT_TOR_TRANSPORT);
        match TorController::verify_transport(transport_port) {
            Ok(_) => {
                transport_ok = true;
                details.push(format!(
                    "tor: TransPort 127.0.0.1:{transport_port} is responding"
                ));
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
        match TorController::verify_dnsport(dns_port) {
            Ok(_) => {
                dnsport_ok = true;
                details.push(format!("tor: DNSPort 127.0.0.1:{dns_port} is responding"));
            }
            Err(e) => {
                details.push(format!("tor: DNSPort 127.0.0.1:{dns_port} failed: {e}"));
            }
        }

        // 5. Check Interface & MAC
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

        // Determine aggregated status
        let status = match (
            active_state.is_some(),
            firewall_ok,
            tor_process_ok,
            transport_ok,
            dnsport_ok,
        ) {
            (true, true, true, true, true) => UmbraStatus::Active,
            (false, false, _, _, _) => UmbraStatus::Inactive,
            (true, false, _, _, _) => UmbraStatus::RecoveryRequired,
            (false, true, _, _, _) => UmbraStatus::RecoveryRequired,
            _ => UmbraStatus::Unknown,
        };

        Ok(VerificationReport {
            status,
            firewall_ok,
            tor_process_ok,
            transport_ok,
            dnsport_ok,
            interface: interface_name,
            live_mac: live_mac_str,
            mac_matches_state,
            details,
        })
    }
}
