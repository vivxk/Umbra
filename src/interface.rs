//! Network interface inspection, egress resolution, and MAC address manipulation.

use std::fs;
use std::path::Path;

use crate::error::{Result, UmbraError};
use crate::mac::MacAddress;

/// Captured baseline interface configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceBaseline {
    pub name: String,
    pub original_mac: MacAddress,
    pub was_up: bool,
}

/// Candidate default route discovered from system routing tables
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub interface: String,
    pub metric: i32,
}

/// Interface controller providing safe inspection and mutation
pub struct InterfaceController;

impl InterfaceController {
    /// Parses /proc/net/route content and returns candidate default routes.
    /// Filters out loopback ("lo") and routes without the RTF_UP flag.
    pub fn parse_default_routes(route_content: &str) -> Vec<RouteCandidate> {
        let mut candidates: Vec<RouteCandidate> = Vec::new();

        // Format of /proc/net/route:
        // Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
        for line in route_content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 7 {
                let iface = fields[0];
                let destination = fields[1];
                let flags_str = fields[3];
                let metric_str = fields[6];

                // Destination 00000000 indicates default route
                if destination == "00000000" && iface != "lo" {
                    let flags = u16::from_str_radix(flags_str, 16).unwrap_or(0);
                    // RTF_UP is 0x0001
                    if (flags & 0x0001) != 0 {
                        let metric = metric_str.parse::<i32>().unwrap_or(0);
                        candidates.push(RouteCandidate {
                            interface: iface.to_string(),
                            metric,
                        });
                    }
                }
            }
        }

        candidates
    }

    /// Extracts unique interface names ordered by metric ascending (lowest metric first).
    pub fn parse_default_route_interfaces(route_content: &str) -> Vec<String> {
        let mut candidates = Self::parse_default_routes(route_content);
        candidates.sort_by_key(|c| c.metric);
        let mut ifaces: Vec<String> = Vec::new();
        for c in candidates {
            if !ifaces.contains(&c.interface) {
                ifaces.push(c.interface);
            }
        }
        ifaces
    }

    /// Parses stdout from `ip route show default` into route candidates
    pub fn parse_ip_route_default_output(stdout: &str) -> Vec<RouteCandidate> {
        let mut candidates = Vec::new();
        for line in stdout.lines() {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = tokens.iter().position(|&x| x == "dev") {
                if let Some(&dev_name) = tokens.get(pos + 1) {
                    if dev_name != "lo" {
                        let metric = if let Some(m_pos) = tokens.iter().position(|&x| x == "metric")
                        {
                            tokens
                                .get(m_pos + 1)
                                .and_then(|m| m.parse::<i32>().ok())
                                .unwrap_or(0)
                        } else {
                            0
                        };
                        candidates.push(RouteCandidate {
                            interface: dev_name.to_string(),
                            metric,
                        });
                    }
                }
            }
        }
        candidates
    }

    /// Resolves the single authoritative egress interface from candidates.
    /// Per Section 93: If multiple distinct interfaces share the lowest metric,
    /// egress is ambiguous and we must fail safely rather than arbitrarily choosing.
    pub fn resolve_authoritative_candidate(candidates: &[RouteCandidate]) -> Result<String> {
        if candidates.is_empty() {
            return Err(UmbraError::EgressResolutionFailed(
                "no active default route discovered".to_string(),
            ));
        }

        let min_metric = candidates
            .iter()
            .map(|c| c.metric)
            .min()
            .expect("candidates non-empty");

        let mut min_interfaces: Vec<&str> = candidates
            .iter()
            .filter(|c| c.metric == min_metric)
            .map(|c| c.interface.as_str())
            .collect();
        min_interfaces.sort_unstable();
        min_interfaces.dedup();

        if min_interfaces.len() > 1 {
            return Err(UmbraError::EgressResolutionFailed(format!(
                "ambiguous default routes: multiple interfaces ({:?}) share lowest metric {}",
                min_interfaces, min_metric
            )));
        }

        Ok(min_interfaces[0].to_string())
    }

    /// Resolves the authoritative default egress interface against a given sysfs root
    pub fn detect_default_egress_with_sysfs(sysfs_root: &Path) -> Result<String> {
        if let Ok(route_content) = fs::read_to_string("/proc/net/route") {
            let candidates = Self::parse_default_routes(&route_content);
            let valid_candidates: Vec<RouteCandidate> = candidates
                .into_iter()
                .filter(|c| sysfs_root.join(&c.interface).exists())
                .collect();

            if !valid_candidates.is_empty() {
                return Self::resolve_authoritative_candidate(&valid_candidates);
            }
        }

        // Fallback: run `ip route show default`
        let output = crate::system::resolve_trusted_command("ip")?
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| {
                UmbraError::EgressResolutionFailed(format!("failed to run ip route show: {e}"))
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let candidates = Self::parse_ip_route_default_output(&stdout);
            let valid_candidates: Vec<RouteCandidate> = candidates
                .into_iter()
                .filter(|c| sysfs_root.join(&c.interface).exists())
                .collect();

            if !valid_candidates.is_empty() {
                return Self::resolve_authoritative_candidate(&valid_candidates);
            }
        }

        Err(UmbraError::EgressResolutionFailed(
            "no active default route discovered".to_string(),
        ))
    }

    /// Resolves the authoritative default egress interface via /proc/net/route (or ip route fallback)
    pub fn detect_default_egress() -> Result<String> {
        Self::detect_default_egress_with_sysfs(Path::new("/sys/class/net"))
    }

    /// Captures the baseline of an interface from a specified sysfs net directory.
    /// Loopback ('lo') and interfaces with all-zero or multicast MACs are rejected.
    pub fn capture_baseline_from_sysfs(
        sysfs_root: &Path,
        iface: &str,
    ) -> Result<InterfaceBaseline> {
        if iface == "lo" {
            return Err(UmbraError::InterfaceNotFound(
                "loopback interface 'lo' cannot be used as egress".to_string(),
            ));
        }

        let sys_path = sysfs_root.join(iface);
        if !sys_path.exists() {
            return Err(UmbraError::InterfaceNotFound(iface.to_string()));
        }

        // Check interface type if available in sysfs: 1 is ARPHRD_ETHER
        let type_path = sys_path.join("type");
        if type_path.exists() {
            if let Ok(content) = fs::read_to_string(&type_path) {
                if let Ok(dev_type) = content.trim().parse::<u32>() {
                    if dev_type != 1 {
                        return Err(UmbraError::InvalidMacAddress(format!(
                            "interface '{iface}' has link type {dev_type} (expected ARPHRD_ETHER 1); tunnel/point-to-point interfaces do not support MAC randomization"
                        )));
                    }
                }
            }
        }

        let original_mac = Self::read_mac_from_sysfs(sysfs_root, iface)?;
        if original_mac.is_all_zeros() {
            return Err(UmbraError::InvalidMacAddress(format!(
                "interface '{iface}' has all-zero MAC address, cannot be safely randomized"
            )));
        }
        if original_mac.is_multicast() {
            return Err(UmbraError::InvalidMacAddress(format!(
                "interface '{iface}' has multicast MAC address, cannot be safely randomized"
            )));
        }

        let was_up = Self::is_administratively_up_from_sysfs(sysfs_root, iface)?;

        Ok(InterfaceBaseline {
            name: iface.to_string(),
            original_mac,
            was_up,
        })
    }

    /// Captures the full baseline of an interface prior to any modification
    pub fn capture_baseline(iface: &str) -> Result<InterfaceBaseline> {
        Self::capture_baseline_from_sysfs(Path::new("/sys/class/net"), iface)
    }

    /// Reads current MAC address from <sysfs_root>/<iface>/address
    pub fn read_mac_from_sysfs(sysfs_root: &Path, iface: &str) -> Result<MacAddress> {
        let addr_path = sysfs_root.join(iface).join("address");
        let content = fs::read_to_string(&addr_path).map_err(|e| {
            UmbraError::InterfaceNotFound(format!(
                "unable to read address for {iface} at {}: {e}",
                addr_path.display()
            ))
        })?;

        MacAddress::parse(&content)
    }

    /// Reads current MAC address from /sys/class/net/<iface>/address
    pub fn read_mac(iface: &str) -> Result<MacAddress> {
        Self::read_mac_from_sysfs(Path::new("/sys/class/net"), iface)
    }

    /// Checks if interface flags indicate administrative UP (IFF_UP = 0x1) from sysfs
    pub fn is_administratively_up_from_sysfs(sysfs_root: &Path, iface: &str) -> Result<bool> {
        let flags_path = sysfs_root.join(iface).join("flags");
        let content = fs::read_to_string(&flags_path).map_err(|e| {
            UmbraError::InterfaceNotFound(format!(
                "unable to read flags for {iface} at {}: {e}",
                flags_path.display()
            ))
        })?;

        let hex_str = content.trim().trim_start_matches("0x");
        let flags = u32::from_str_radix(hex_str, 16).map_err(|_| {
            UmbraError::InterfaceStateChangeFailed {
                interface: iface.to_string(),
                reason: format!("invalid hex flags in '{content}'"),
            }
        })?;

        // 0x1 is IFF_UP
        Ok((flags & 0x1) != 0)
    }

    /// Checks if interface flags indicate administrative UP (IFF_UP = 0x1)
    pub fn is_administratively_up(iface: &str) -> Result<bool> {
        Self::is_administratively_up_from_sysfs(Path::new("/sys/class/net"), iface)
    }

    /// Sets interface administrative state UP or DOWN using ip link
    pub fn set_admin_state(iface: &str, up: bool) -> Result<()> {
        let state_arg = if up { "up" } else { "down" };
        let output = crate::system::resolve_trusted_command("ip")?
            .args(["link", "set", "dev", iface, state_arg])
            .output()
            .map_err(|e| UmbraError::InterfaceStateChangeFailed {
                interface: iface.to_string(),
                reason: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UmbraError::InterfaceStateChangeFailed {
                interface: iface.to_string(),
                reason: stderr.trim().to_string(),
            });
        }

        Ok(())
    }

    /// Changes the interface MAC address with verification:
    /// 1. Rejects loopback 'lo' and non-randomized MACs
    /// 2. Brings interface down if up
    /// 3. Sets new MAC
    /// 4. Restores original administrative state
    /// 5. Verifies live MAC and admin state match
    pub fn apply_mac(iface: &str, new_mac: MacAddress) -> Result<()> {
        if iface == "lo" {
            return Err(UmbraError::MacChangeFailed {
                interface: iface.to_string(),
                reason: "cannot change MAC on loopback interface 'lo'".to_string(),
            });
        }

        if !new_mac.is_valid_randomized() {
            return Err(UmbraError::InvalidMacAddress(format!(
                "MAC '{new_mac}' is not a valid locally administered unicast MAC"
            )));
        }

        let was_up = Self::is_administratively_up(iface)?;

        if was_up {
            Self::set_admin_state(iface, false)?;
        }

        let mac_str = new_mac.to_string();
        let output = crate::system::resolve_trusted_command("ip")?
            .args(["link", "set", "dev", iface, "address", &mac_str])
            .output()
            .map_err(|e| UmbraError::MacChangeFailed {
                interface: iface.to_string(),
                reason: e.to_string(),
            })?;

        let change_err = if !output.status.success() {
            Some(String::from_utf8_lossy(&output.stderr).trim().to_string())
        } else {
            None
        };

        // Always attempt to restore original administrative state
        let admin_restore_res = if was_up {
            Self::set_admin_state(iface, true)
        } else {
            Ok(())
        };

        if let Some(err) = change_err {
            return Err(UmbraError::MacChangeFailed {
                interface: iface.to_string(),
                reason: err,
            });
        }

        admin_restore_res?;

        // Live verification of MAC
        let live_mac = Self::read_mac(iface)?;
        if live_mac != new_mac {
            return Err(UmbraError::MacVerificationMismatch {
                interface: iface.to_string(),
                expected: new_mac.to_string(),
                actual: live_mac.to_string(),
            });
        }

        // Live verification of administrative state
        let live_up = Self::is_administratively_up(iface)?;
        if live_up != was_up {
            return Err(UmbraError::InterfaceStateChangeFailed {
                interface: iface.to_string(),
                reason: format!(
                    "admin state mismatch after MAC change: expected up={was_up}, actual={live_up}"
                ),
            });
        }

        Ok(())
    }

    /// Restores the original baseline MAC and admin state with verification
    pub fn restore_baseline(baseline: &InterfaceBaseline) -> Result<()> {
        if baseline.name == "lo" {
            return Err(UmbraError::MacRestoreFailed {
                interface: baseline.name.clone(),
                reason: "cannot restore MAC on loopback interface 'lo'".to_string(),
            });
        }

        let was_up = Self::is_administratively_up(&baseline.name)?;

        if was_up {
            Self::set_admin_state(&baseline.name, false)?;
        }

        let orig_mac_str = baseline.original_mac.to_string();
        let output = crate::system::resolve_trusted_command("ip")?
            .args([
                "link",
                "set",
                "dev",
                &baseline.name,
                "address",
                &orig_mac_str,
            ])
            .output()
            .map_err(|e| UmbraError::MacRestoreFailed {
                interface: baseline.name.clone(),
                reason: e.to_string(),
            })?;

        let restore_err = if !output.status.success() {
            Some(String::from_utf8_lossy(&output.stderr).trim().to_string())
        } else {
            None
        };

        // Restore administrative state to baseline
        let admin_restore_res = Self::set_admin_state(&baseline.name, baseline.was_up);

        if let Some(err) = restore_err {
            return Err(UmbraError::MacRestoreFailed {
                interface: baseline.name.clone(),
                reason: err,
            });
        }

        admin_restore_res?;

        // Live verification of MAC
        let live_mac = Self::read_mac(&baseline.name)?;
        if live_mac != baseline.original_mac {
            return Err(UmbraError::MacVerificationMismatch {
                interface: baseline.name.clone(),
                expected: baseline.original_mac.to_string(),
                actual: live_mac.to_string(),
            });
        }

        // Live verification of administrative state
        let live_up = Self::is_administratively_up(&baseline.name)?;
        if live_up != baseline.was_up {
            return Err(UmbraError::InterfaceStateChangeFailed {
                interface: baseline.name.clone(),
                reason: format!(
                    "admin state mismatch after restoration: expected up={}, actual={}",
                    baseline.was_up, live_up
                ),
            });
        }

        Ok(())
    }
}
