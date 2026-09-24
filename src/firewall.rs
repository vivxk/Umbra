//! nftables firewall controller, ownership authentication, and atomic policy management.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::constants::{
    DEFAULT_TOR_CONTROLPORT, DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT, NFT_TABLE_FAMILY,
    NFT_TABLE_NAME, OWNERSHIP_MARKER,
};
use crate::error::{Result, UmbraError};

/// Firewall configuration parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallConfig {
    pub table_name: String,
    pub table_family: String,
    pub tor_uid: u32,
    pub tor_transport_port: u16,
    pub tor_dns_port: u16,
    pub tor_control_port: u16,
    pub egress_interface: String,
    pub activation_id: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            table_name: NFT_TABLE_NAME.to_string(),
            table_family: NFT_TABLE_FAMILY.to_string(),
            tor_uid: 0,
            tor_transport_port: DEFAULT_TOR_TRANSPORT,
            tor_dns_port: DEFAULT_TOR_DNSPORT,
            tor_control_port: DEFAULT_TOR_CONTROLPORT,
            egress_interface: String::new(),
            activation_id: String::new(),
        }
    }
}

pub struct FirewallController;

impl FirewallController {
    /// Generates the complete, atomic nftables ruleset specification
    pub fn generate_ruleset(config: &FirewallConfig) -> String {
        format!(
            r#"table {family} {table} {{
    chain output_nat {{
        type nat hook output priority dstnat; policy accept;
        skuid {tor_uid} return comment "{marker}"
        oif "lo" return comment "{marker}"
        udp dport 53 redirect to :{tor_dns_port} comment "{marker}"
        ip daddr 127.0.0.0/8 return comment "{marker}"
        tcp dport != {tor_transport_port} redirect to :{tor_transport_port} comment "{marker}"
    }}

    chain output_filter {{
        type filter hook output priority filter; policy drop;
        oif "lo" accept comment "{marker}"
        ct state established,related accept comment "{marker}"
        skuid {tor_uid} accept comment "{marker}"
        ip daddr 127.0.0.1 tcp dport {tor_transport_port} accept comment "{marker}"
        ip daddr 127.0.0.1 udp dport {tor_dns_port} accept comment "{marker}"
        ip daddr 127.0.0.1 tcp dport {tor_control_port} accept comment "{marker}"
        tcp dport 53 reject with tcp reset comment "{marker}"
        meta l4proto udp drop comment "{marker}"
        ip6 daddr != ::1 drop comment "{marker}"
    }}
}}
"#,
            family = config.table_family,
            table = config.table_name,
            tor_uid = config.tor_uid,
            tor_dns_port = config.tor_dns_port,
            tor_transport_port = config.tor_transport_port,
            tor_control_port = config.tor_control_port,
            marker = OWNERSHIP_MARKER
        )
    }

    /// Verifies the syntax of the generated ruleset without applying it (nft -c -f -)
    pub fn check_syntax(ruleset: &str) -> Result<()> {
        let run_check =
            |use_unshare: bool| -> std::result::Result<std::process::Output, std::io::Error> {
                let mut cmd = if use_unshare {
                    let mut c = Command::new("unshare");
                    c.args(["-r", "-n", "nft", "-c", "-f", "-"]);
                    c
                } else {
                    let mut c = Command::new("nft");
                    c.args(["-c", "-f", "-"]);
                    c
                };

                let mut child = cmd
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;

                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(ruleset.as_bytes())?;
                }

                child.wait_with_output()
            };

        // First attempt standard nft -c -f -
        let output = match run_check(false) {
            Ok(out) => {
                if !out.status.success() {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    if stderr.contains("Operation not permitted") {
                        // Retry inside unprivileged user namespace if unshare is available
                        run_check(true).map_err(|e| {
                            UmbraError::FirewallInstallFailed(format!(
                                "failed to spawn unshare nft: {e}"
                            ))
                        })?
                    } else {
                        out
                    }
                } else {
                    out
                }
            }
            Err(e) => {
                return Err(UmbraError::FirewallInstallFailed(format!(
                    "failed to spawn nft -c: {e}"
                )));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UmbraError::FirewallInstallFailed(format!(
                "nft syntax check failed: {stderr}"
            )));
        }

        Ok(())
    }

    /// Atomically applies the ruleset to the kernel via nft -f -
    pub fn install(config: &FirewallConfig) -> Result<()> {
        let ruleset = Self::generate_ruleset(config);

        // Pre-validate syntax before kernel application
        Self::check_syntax(&ruleset)?;

        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| UmbraError::FirewallInstallFailed(format!("failed to spawn nft: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(ruleset.as_bytes()).map_err(|e| {
                UmbraError::FirewallInstallFailed(format!("failed to write ruleset: {e}"))
            })?;
        }

        let output = child.wait_with_output().map_err(|e| {
            UmbraError::FirewallInstallFailed(format!("failed waiting for nft: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UmbraError::FirewallInstallFailed(format!(
                "nft ruleset application failed: {stderr}"
            )));
        }

        // Immediately verify live kernel state
        Self::verify_live(config)
    }

    /// Checks if the table currently exists in the kernel
    pub fn table_exists(family: &str, table: &str) -> Result<bool> {
        let output = Command::new("nft")
            .args(["list", "table", family, table])
            .output()
            .map_err(|e| {
                UmbraError::FirewallVerificationFailed(format!("failed to run nft list table: {e}"))
            })?;

        if output.status.success() {
            Ok(true)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("No such file or directory")
                || stderr.contains("does not exist")
                || stderr.contains("no such table")
            {
                Ok(false)
            } else {
                Err(UmbraError::FirewallVerificationFailed(format!(
                    "unexpected error querying nft table: {stderr}"
                )))
            }
        }
    }

    /// Authenticates that the given ruleset text contains the required ownership marker
    pub fn authenticate_ruleset_text(ruleset: &str) -> Result<()> {
        if ruleset.trim().is_empty() {
            return Err(UmbraError::FirewallOwnershipUnknown(
                "empty ruleset cannot be authenticated".to_string(),
            ));
        }

        if !ruleset.contains(OWNERSHIP_MARKER) {
            return Err(UmbraError::FirewallOwnershipUnknown(format!(
                "ruleset missing required ownership marker '{OWNERSHIP_MARKER}'"
            )));
        }

        Ok(())
    }

    /// Authenticates that the live table is strictly owned by Umbra
    pub fn authenticate_ownership(family: &str, table: &str) -> Result<()> {
        let output = Command::new("nft")
            .args(["list", "table", family, table])
            .output()
            .map_err(|e| {
                UmbraError::FirewallOwnershipUnknown(format!("failed to inspect table: {e}"))
            })?;

        if !output.status.success() {
            return Err(UmbraError::FirewallOwnershipUnknown(format!(
                "table {family} {table} not found or inaccessible"
            )));
        }

        let content = String::from_utf8_lossy(&output.stdout);
        Self::authenticate_ruleset_text(&content).map_err(|_| {
            UmbraError::FirewallOwnershipUnknown(format!(
                "table {family} {table} missing required ownership marker '{OWNERSHIP_MARKER}'"
            ))
        })
    }

    /// Verifies live enforcement: table exists, ownership authenticated, required chains active
    pub fn verify_live(config: &FirewallConfig) -> Result<()> {
        if !Self::table_exists(&config.table_family, &config.table_name)? {
            return Err(UmbraError::FirewallVerificationFailed(format!(
                "table {} {} does not exist in kernel",
                config.table_family, config.table_name
            )));
        }

        Self::authenticate_ownership(&config.table_family, &config.table_name)?;

        let output = Command::new("nft")
            .args(["list", "table", &config.table_family, &config.table_name])
            .output()
            .map_err(|e| {
                UmbraError::FirewallVerificationFailed(format!("failed to list live table: {e}"))
            })?;

        let ruleset_str = String::from_utf8_lossy(&output.stdout);

        if !ruleset_str.contains("chain output_nat") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing chain output_nat".to_string(),
            ));
        }
        if !ruleset_str.contains("chain output_filter") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing chain output_filter".to_string(),
            ));
        }

        Ok(())
    }

    /// Safely deletes the Umbra-owned table after strictly verifying ownership
    pub fn teardown(family: &str, table: &str) -> Result<()> {
        if !Self::table_exists(family, table)? {
            // Table already absent - nothing to remove
            return Ok(());
        }

        // Enforce ownership verification before deletion
        Self::authenticate_ownership(family, table)?;

        let output = Command::new("nft")
            .args(["delete", "table", family, table])
            .output()
            .map_err(|e| {
                UmbraError::FirewallTeardownFailed(format!("failed to delete table: {e}"))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UmbraError::FirewallTeardownFailed(format!(
                "nft delete table failed: {stderr}"
            )));
        }

        // Verify absence
        if Self::table_exists(family, table)? {
            return Err(UmbraError::FirewallTeardownFailed(format!(
                "table {family} {table} still present after deletion"
            )));
        }

        Ok(())
    }
}
