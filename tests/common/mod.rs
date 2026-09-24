#![allow(dead_code)]

use std::env;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(1);

pub const NETNS_ENV_VAR: &str = "UMBRA_TEST_NETNS";

/// Returns true if the current execution is running inside an isolated test network namespace.
pub fn is_in_isolated_netns() -> bool {
    env::var(NETNS_ENV_VAR).is_ok()
}

pub enum IsolationBackend {
    IpNetns(String),
    Unshare,
}

/// RAII Guard managing lifecycle of an isolated Linux network namespace (`ip netns`).
pub struct IsolatedNetns {
    pub name: String,
    pub backend: IsolationBackend,
}

impl IsolatedNetns {
    /// Creates a new uniquely named network namespace.
    /// Prefers `sudo -n ip netns add` with fallback to `unshare -r -n`.
    pub fn new(prefix: &str) -> Option<Self> {
        let unique_id = format!(
            "{prefix}_{}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
                % 1_000_000,
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );

        // Try `sudo -n ip netns add <unique_id>`
        let status = Command::new("sudo")
            .args(["-n", "ip", "netns", "add", &unique_id])
            .status();

        if let Ok(st) = status {
            if st.success() {
                // Bring lo up in the new network namespace
                let _ = Command::new("sudo")
                    .args([
                        "-n", "ip", "netns", "exec", &unique_id, "ip", "link", "set", "lo", "up",
                    ])
                    .status();

                return Some(Self {
                    name: unique_id.clone(),
                    backend: IsolationBackend::IpNetns(unique_id),
                });
            }
        }

        // Fallback: test if unshare -r -n works
        let unshare_status = Command::new("unshare")
            .args(["-r", "-n", "ip", "link"])
            .status();

        if let Ok(st) = unshare_status {
            if st.success() {
                return Some(Self {
                    name: unique_id,
                    backend: IsolationBackend::Unshare,
                });
            }
        }

        None
    }

    /// Re-executes the current test inside the isolated network namespace.
    pub fn run_test(&self, test_name: &str) {
        let current_exe = env::current_exe().expect("failed to determine current test executable");

        let output = match &self.backend {
            IsolationBackend::IpNetns(name) => Command::new("sudo")
                .args(["-E", "ip", "netns", "exec", name])
                .arg(&current_exe)
                .args([test_name, "--exact", "--nocapture"])
                .env(NETNS_ENV_VAR, name)
                .output()
                .expect("failed to execute test in ip netns"),
            IsolationBackend::Unshare => Command::new("unshare")
                .args(["-r", "-n"])
                .arg(&current_exe)
                .args([test_name, "--exact", "--nocapture"])
                .env(NETNS_ENV_VAR, &self.name)
                .output()
                .expect("failed to execute test in unshare netns"),
        };

        if !output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            panic!(
                "Test '{test_name}' failed inside isolated network namespace '{}'.\nStdout:\n{}\nStderr:\n{}",
                self.name, stdout, stderr
            );
        }
    }

    /// Adds a dummy interface to this network namespace
    pub fn add_dummy_interface(&self, iface_name: &str, mac: Option<&str>, up: bool) -> Output {
        match &self.backend {
            IsolationBackend::IpNetns(name) => {
                let _ = Command::new("sudo")
                    .args([
                        "-n", "ip", "netns", "exec", name, "ip", "link", "add", "dev", iface_name,
                        "type", "dummy",
                    ])
                    .output();

                if let Some(mac_str) = mac {
                    let _ = Command::new("sudo")
                        .args([
                            "-n", "ip", "netns", "exec", name, "ip", "link", "set", "dev",
                            iface_name, "address", mac_str,
                        ])
                        .output();
                }

                if up {
                    let _ = Command::new("sudo")
                        .args([
                            "-n", "ip", "netns", "exec", name, "ip", "link", "set", "dev",
                            iface_name, "up",
                        ])
                        .output();
                }

                Command::new("sudo")
                    .args([
                        "-n", "ip", "netns", "exec", name, "ip", "link", "show", "dev", iface_name,
                    ])
                    .output()
                    .expect("ip link show failed")
            }
            IsolationBackend::Unshare => Command::new("unshare")
                .args(["-r", "-n", "ip", "link"])
                .output()
                .expect("unshare ip link"),
        }
    }
}

impl Drop for IsolatedNetns {
    fn drop(&mut self) {
        if let IsolationBackend::IpNetns(ref name) = self.backend {
            let _ = Command::new("sudo")
                .args(["-n", "ip", "netns", "del", name])
                .output();
        }
    }
}
