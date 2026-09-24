//! Network interface inspection, egress resolution, and MAC address manipulation.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::error::{Result, UmbraError};
use crate::mac::MacAddress;

/// Captured baseline interface configuration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceBaseline {
    pub name: String,
    pub original_mac: MacAddress,
    pub was_up: bool,
}

/// Interface controller providing safe inspection and mutation
pub struct InterfaceController;

impl InterfaceController {
    /// Parses /proc/net/route content and returns candidate default route interfaces ordered by metric (lowest metric first).
    /// Filters out loopback ("lo") and routes without the RTF_UP flag.
    pub fn parse_default_routes(route_content: &str) -> Vec<String> {
        let mut candidates: Vec<(i32, String)> = Vec::new();

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
                        candidates.push((metric, iface.to_string()));
                    }
                }
            }
        }

        // Sort by metric ascending (lowest metric has highest routing priority)
        candidates.sort_by_key(|&(metric, _)| metric);
        candidates.into_iter().map(|(_, iface)| iface).collect()
    }

    /// Resolves the authoritative default egress interface via /proc/net/route (or ip route fallback)
    pub fn detect_default_egress() -> Result<String> {
        if let Ok(route_content) = fs::read_to_string("/proc/net/route") {
            let candidates = Self::parse_default_routes(&route_content);
            for iface in candidates {
                if Path::new("/sys/class/net").join(&iface).exists() {
                    return Ok(iface);
                }
            }
        }

        // Fallback: run `ip route show default`
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .map_err(|e| {
                UmbraError::EgressResolutionFailed(format!("failed to run ip route show: {e}"))
            })?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let parts: Vec<&str> = stdout.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&x| x == "dev") {
                if let Some(dev_name) = parts.get(pos + 1) {
                    if *dev_name != "lo" && Path::new("/sys/class/net").join(dev_name).exists() {
                        return Ok(dev_name.to_string());
                    }
                }
            }
        }

        Err(UmbraError::EgressResolutionFailed(
            "no active default route discovered".to_string(),
        ))
    }

    /// Captures the baseline of an interface from a specified sysfs net directory
    pub fn capture_baseline_from_sysfs(
        sysfs_root: &Path,
        iface: &str,
    ) -> Result<InterfaceBaseline> {
        let sys_path = sysfs_root.join(iface);
        if !sys_path.exists() {
            return Err(UmbraError::InterfaceNotFound(iface.to_string()));
        }

        let original_mac = Self::read_mac_from_sysfs(sysfs_root, iface)?;
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
            UmbraError::InterfaceNotFound(format!("invalid hex flags in '{content}'"))
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
        let output = Command::new("ip")
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
    /// 1. Brings interface down if up
    /// 2. Sets new MAC
    /// 3. Restores administrative state
    /// 4. Verifies live MAC and admin state match
    pub fn apply_mac(iface: &str, new_mac: MacAddress) -> Result<()> {
        let was_up = Self::is_administratively_up(iface)?;

        if was_up {
            Self::set_admin_state(iface, false)?;
        }

        let mac_str = new_mac.to_string();
        let output = Command::new("ip")
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

        // Always restore original administrative state
        if was_up {
            let _ = Self::set_admin_state(iface, true);
        }

        if let Some(err) = change_err {
            return Err(UmbraError::MacChangeFailed {
                interface: iface.to_string(),
                reason: err,
            });
        }

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
        let was_up = Self::is_administratively_up(&baseline.name)?;

        if was_up {
            Self::set_admin_state(&baseline.name, false)?;
        }

        let orig_mac_str = baseline.original_mac.to_string();
        let output = Command::new("ip")
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
        let _ = Self::set_admin_state(&baseline.name, baseline.was_up);

        if let Some(err) = restore_err {
            return Err(UmbraError::MacRestoreFailed {
                interface: baseline.name.clone(),
                reason: err,
            });
        }

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
