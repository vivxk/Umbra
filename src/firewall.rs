//! nftables firewall controller, ownership authentication, and atomic policy management.

use std::io::Write;
use std::process::Stdio;

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
    /// Generates the complete, atomic nftables ruleset specification.
    /// Invariants enforced:
    /// 1. Tor UID is exempt from NAT redirection and filter drops.
    /// 2. External IPv6 is completely dropped (Section 23 Strategy B) and never redirected.
    /// 3. UDP DNS (dport 53) is intercepted and redirected to Tor DNSPort.
    /// 4. TCP DNS (dport 53) is rejected with TCP reset (never redirected to TransPort per Section 20).
    /// 5. Non-Tor application TCP is redirected to Tor TransPort.
    /// 6. Arbitrary UDP and QUIC are blocked fail-closed.
    /// 7. Loopback IPC communications are preserved.
    /// 8. Pre-existing direct flows cannot bypass policy (no blanket ct state established accept).
    /// 9. Unique activation identifier binds ruleset to active runtime session.
    pub fn generate_ruleset(config: &FirewallConfig) -> String {
        let marker = if config.activation_id.trim().is_empty() {
            OWNERSHIP_MARKER.to_string()
        } else {
            format!("{}:{}", OWNERSHIP_MARKER, config.activation_id.trim())
        };

        format!(
            r#"table {family} {table} {{
    chain output_nat {{
        type nat hook output priority dstnat; policy accept;
        skuid {tor_uid} return comment "{marker}"
        meta nfproto ipv6 return comment "{marker}"
        udp dport 53 redirect to :{tor_dns_port} comment "{marker}"
        oif "lo" return comment "{marker}"
        ip daddr 127.0.0.0/8 return comment "{marker}"
        tcp dport 53 return comment "{marker}"
        tcp dport 853 return comment "{marker}"
        tcp dport != {tor_transport_port} redirect to :{tor_transport_port} comment "{marker}"
    }}

    chain output_filter {{
        type filter hook output priority filter; policy drop;
        skuid {tor_uid} accept comment "{marker}"
        meta nfproto ipv6 udp dport 53 drop comment "{marker}"
        meta nfproto ipv6 tcp dport 53 drop comment "{marker}"
        tcp dport 53 reject with tcp reset comment "{marker}"
        udp dport 443 drop comment "{marker}"
        tcp dport 853 drop comment "{marker}"
        udp dport 853 drop comment "{marker}"
        ip6 daddr != ::1 drop comment "{marker}"
        ip daddr 127.0.0.1 tcp dport {tor_transport_port} accept comment "{marker}"
        ip daddr 127.0.0.1 udp dport {tor_dns_port} accept comment "{marker}"
        ip daddr 127.0.0.1 tcp dport {tor_control_port} accept comment "{marker}"
        oif "lo" accept comment "{marker}"
        meta l4proto udp drop comment "{marker}"
    }}
}}
"#,
            family = config.table_family,
            table = config.table_name,
            tor_uid = config.tor_uid,
            tor_dns_port = config.tor_dns_port,
            tor_transport_port = config.tor_transport_port,
            tor_control_port = config.tor_control_port,
            marker = marker
        )
    }

    /// Verifies the syntax of the generated ruleset without applying it (nft -c -f -).
    /// Normalizes CRLF line terminators to LF to avoid nft syntax errors.
    pub fn check_syntax(ruleset: &str) -> Result<()> {
        let normalized = ruleset.replace("\r\n", "\n");
        let run_check =
            |use_unshare: bool| -> std::result::Result<std::process::Output, std::io::Error> {
                let mut cmd = if use_unshare {
                    let mut c = crate::system::resolve_trusted_command("unshare")
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    c.args(["-r", "-n", "nft", "-c", "-f", "-"]);
                    c
                } else {
                    let mut c = crate::system::resolve_trusted_command("nft")
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    c.args(["-c", "-f", "-"]);
                    c
                };

                let mut child = cmd
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()?;

                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(normalized.as_bytes())?;
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
        let normalized = ruleset.replace("\r\n", "\n");

        // Pre-validate syntax before kernel application
        Self::check_syntax(&normalized)?;

        let mut child = crate::system::resolve_trusted_command("nft")?
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| UmbraError::FirewallInstallFailed(format!("failed to spawn nft: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(normalized.as_bytes()).map_err(|e| {
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
        let output = crate::system::resolve_trusted_command("nft")?
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

    /// Authenticates that the live table is strictly owned by Umbra and matches activation_id if specified
    pub fn authenticate_ownership_with_id(
        family: &str,
        table: &str,
        expected_activation_id: Option<&str>,
    ) -> Result<()> {
        let output = crate::system::resolve_trusted_command("nft")?
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
        })?;

        if let Some(act_id) = expected_activation_id {
            if !act_id.trim().is_empty() {
                let expected_marker = format!("{OWNERSHIP_MARKER}:{act_id}");
                if !content.contains(&expected_marker) && !content.contains(act_id) {
                    return Err(UmbraError::FirewallOwnershipUnknown(format!(
                        "table {family} {table} activation ID mismatch: expected {act_id}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Authenticates that the live table is strictly owned by Umbra
    pub fn authenticate_ownership(family: &str, table: &str) -> Result<()> {
        Self::authenticate_ownership_with_id(family, table, None)
    }

    /// Verifies live enforcement: table exists, ownership authenticated (including activation ID),
    /// required base chains and hooks active, and security policies active.
    pub fn verify_live(config: &FirewallConfig) -> Result<()> {
        if !Self::table_exists(&config.table_family, &config.table_name)? {
            return Err(UmbraError::FirewallVerificationFailed(format!(
                "table {} {} does not exist in kernel",
                config.table_family, config.table_name
            )));
        }

        let expected_act_id = if config.activation_id.trim().is_empty() {
            None
        } else {
            Some(config.activation_id.trim())
        };
        Self::authenticate_ownership_with_id(
            &config.table_family,
            &config.table_name,
            expected_act_id,
        )?;

        // Structured JSON inspection via nft -j list table
        let json_output = crate::system::resolve_trusted_command("nft")?
            .args([
                "-j",
                "list",
                "table",
                &config.table_family,
                &config.table_name,
            ])
            .output();

        let mut structured_verified = false;
        if let Ok(ref out) = json_output {
            if out.status.success() {
                if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&out.stdout) {
                    if let Some(items) = val.get("nftables").and_then(|v| v.as_array()) {
                        let mut has_nat_chain = false;
                        let mut has_filter_chain = false;

                        for item in items {
                            if let Some(chain) = item.get("chain") {
                                let cname = chain
                                    .get("name")
                                    .and_then(|n| n.as_str())
                                    .unwrap_or_default();
                                let ctype = chain
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .unwrap_or_default();
                                let chook = chain
                                    .get("hook")
                                    .and_then(|h| h.as_str())
                                    .unwrap_or_default();
                                let cpolicy = chain
                                    .get("policy")
                                    .and_then(|p| p.as_str())
                                    .unwrap_or_default();

                                if cname == "output_nat" {
                                    if ctype != "nat" || chook != "output" || cpolicy != "accept" {
                                        return Err(UmbraError::FirewallVerificationFailed(format!(
                                            "chain output_nat has invalid configuration: type={ctype}, hook={chook}, policy={cpolicy}"
                                        )));
                                    }
                                    has_nat_chain = true;
                                } else if cname == "output_filter" {
                                    if ctype != "filter" || chook != "output" || cpolicy != "drop" {
                                        return Err(UmbraError::FirewallVerificationFailed(format!(
                                            "chain output_filter has invalid configuration: type={ctype}, hook={chook}, policy={cpolicy}"
                                        )));
                                    }
                                    has_filter_chain = true;
                                }
                            }
                        }

                        if !has_nat_chain {
                            return Err(UmbraError::FirewallVerificationFailed(
                                "live ruleset missing base chain output_nat".to_string(),
                            ));
                        }
                        if !has_filter_chain {
                            return Err(UmbraError::FirewallVerificationFailed(
                                "live ruleset missing base chain output_filter".to_string(),
                            ));
                        }
                        structured_verified = true;
                    }
                }
            }
        }

        let output = crate::system::resolve_trusted_command("nft")?
            .args(["list", "table", &config.table_family, &config.table_name])
            .output()
            .map_err(|e| {
                UmbraError::FirewallVerificationFailed(format!("failed to list live table: {e}"))
            })?;

        let ruleset_str = String::from_utf8_lossy(&output.stdout);

        if !structured_verified {
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
        }

        // Verify Tor UID exceptions
        let expected_tor_nat = format!("skuid {} return", config.tor_uid);
        if !ruleset_str.contains(&expected_tor_nat) {
            return Err(UmbraError::FirewallVerificationFailed(format!(
                "live ruleset missing Tor UID NAT return rule: {expected_tor_nat}"
            )));
        }
        let expected_tor_filter = format!("skuid {} accept", config.tor_uid);
        if !ruleset_str.contains(&expected_tor_filter) {
            return Err(UmbraError::FirewallVerificationFailed(format!(
                "live ruleset missing Tor UID filter accept rule: {expected_tor_filter}"
            )));
        }

        // Verify Redirection rules
        let expected_dns_redirect = format!("redirect to :{}", config.tor_dns_port);
        if !ruleset_str.contains(&expected_dns_redirect) {
            return Err(UmbraError::FirewallVerificationFailed(format!(
                "live ruleset missing dns redirection rule: {expected_dns_redirect}"
            )));
        }
        let expected_transport_redirect = format!("redirect to :{}", config.tor_transport_port);
        if !ruleset_str.contains(&expected_transport_redirect) {
            return Err(UmbraError::FirewallVerificationFailed(format!(
                "live ruleset missing transport redirection rule: {expected_transport_redirect}"
            )));
        }

        // Verify DNS and leak protection policies
        if !ruleset_str.contains("tcp dport 53 reject with tcp reset") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing tcp dport 53 reset rule".to_string(),
            ));
        }
        if !ruleset_str.contains("udp dport 443 drop") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing quic udp 443 drop rule".to_string(),
            ));
        }
        if !ruleset_str.contains("tcp dport 853 drop") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing dot tcp 853 drop rule".to_string(),
            ));
        }
        if !ruleset_str.contains("udp dport 853 drop") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing dot udp 853 drop rule".to_string(),
            ));
        }
        if !ruleset_str.contains("meta nfproto ipv6 udp dport 53 drop") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing ipv6 udp 53 drop rule".to_string(),
            ));
        }
        if !ruleset_str.contains("meta nfproto ipv6 tcp dport 53 drop") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing ipv6 tcp 53 drop rule".to_string(),
            ));
        }
        if !ruleset_str.contains("meta l4proto udp drop") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing udp drop rule".to_string(),
            ));
        }
        if !ruleset_str.contains("ip6 daddr != ::1 drop") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing ipv6 drop rule".to_string(),
            ));
        }
        if !ruleset_str.contains("oif \"lo\" accept") {
            return Err(UmbraError::FirewallVerificationFailed(
                "live ruleset missing loopback accept rule".to_string(),
            ));
        }

        Ok(())
    }

    /// Safely deletes the Umbra-owned table after strictly verifying ownership and activation ID
    pub fn teardown_with_id(
        family: &str,
        table: &str,
        expected_activation_id: Option<&str>,
    ) -> Result<()> {
        if !Self::table_exists(family, table)? {
            // Table already absent - nothing to remove
            return Ok(());
        }

        // Enforce ownership and activation ID verification before deletion
        Self::authenticate_ownership_with_id(family, table, expected_activation_id)?;

        let output = crate::system::resolve_trusted_command("nft")?
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

    /// Safely deletes the Umbra-owned table after strictly verifying ownership
    pub fn teardown(family: &str, table: &str) -> Result<()> {
        Self::teardown_with_id(family, table, None)
    }
}
