//! Constants for Umbra privacy boundary controller.

/// nftables table name owned by Umbra
pub const NFT_TABLE_NAME: &str = "umbra";

/// nftables table family (`inet` covers both IPv4 and IPv6)
pub const NFT_TABLE_FAMILY: &str = "inet";

/// Ownership comment tag attached to rules and chains
pub const OWNERSHIP_MARKER: &str = "umbra-managed";

/// Default Tor transparent proxy port
pub const DEFAULT_TOR_TRANSPORT: u16 = 9040;

/// Default Tor DNS port
pub const DEFAULT_TOR_DNSPORT: u16 = 5353;

/// Default Tor ControlPort
pub const DEFAULT_TOR_CONTROLPORT: u16 = 9051;

/// Local loopback bind IP
pub const LOCAL_LOOPBACK_IPV4: &str = "127.0.0.1";

/// Standard volatile runtime directory
pub const RUNTIME_DIR: &str = "/run/umbra";

/// Active session state file path
pub const RUNTIME_STATE_FILE: &str = "/run/umbra/active.json";

/// Process single-instance lock file path
pub const LOCK_FILE: &str = "/run/umbra/umbra.lock";

/// Primary known unprivileged Tor accounts on Linux distributions
pub const KNOWN_TOR_USERS: &[&str] = &["debian-tor", "tor", "_tor"];

/// Default path for Umbra-managed Tor configuration fragment
pub const DEFAULT_TOR_CONFIG_FRAGMENT: &str = "/etc/tor/torrc.d/umbra.conf";

/// Trusted filesystem prefixes for Tor binary execution
pub const TRUSTED_TOR_PREFIXES: &[&str] = &["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

/// Standard candidate locations for Tor control authentication cookie
pub const KNOWN_TOR_COOKIE_PATHS: &[&str] = &[
    "/run/tor/control.authcookie",
    "/var/run/tor/control.authcookie",
    "/var/lib/tor/control_auth_cookie",
    "/etc/tor/control_auth_cookie",
];
