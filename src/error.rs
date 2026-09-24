//! Strongly typed errors for Umbra.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, UmbraError>;

#[derive(Error, Debug)]
pub enum UmbraError {
    #[error("Egress interface '{0}' not found")]
    InterfaceNotFound(String),

    #[error("Unable to determine default egress interface: {0}")]
    EgressResolutionFailed(String),

    #[error("Invalid MAC address: {0}")]
    InvalidMacAddress(String),

    #[error("Failed to generate valid locally administered unicast MAC: {0}")]
    MacGenerationFailed(String),

    #[error("Failed to change MAC address on interface '{interface}': {reason}")]
    MacChangeFailed { interface: String, reason: String },

    #[error("Failed to restore MAC address on interface '{interface}': {reason}")]
    MacRestoreFailed { interface: String, reason: String },

    #[error(
        "MAC address verification failed for '{interface}': expected {expected}, found {actual}"
    )]
    MacVerificationMismatch {
        interface: String,
        expected: String,
        actual: String,
    },

    #[error("Interface administrative state change failed for '{interface}': {reason}")]
    InterfaceStateChangeFailed { interface: String, reason: String },

    #[error("Firewall installation failed: {0}")]
    FirewallInstallFailed(String),

    #[error("Firewall verification failed: {0}")]
    FirewallVerificationFailed(String),

    #[error("Firewall ownership unknown or untrusted: {0}")]
    FirewallOwnershipUnknown(String),

    #[error("Firewall teardown failed: {0}")]
    FirewallTeardownFailed(String),

    #[error("Tor service is not running")]
    TorNotRunning,

    #[error("Tor process with PID {0} not found")]
    TorProcessNotFound(u32),

    #[error("Process {pid} is not Tor (comm is '{comm}')")]
    TorProcessMismatch { pid: u32, comm: String },

    #[error("Tor executable untrusted: {0}")]
    TorExecutableUntrusted(String),

    #[error("Tor process runs with root privileges (UID 0), which is forbidden")]
    TorRunningAsRoot,

    #[error("Tor identity verification failed: {0}")]
    TorIdentityUnknown(String),

    #[error("Multiple valid Tor processes found; selection is ambiguous: {0}")]
    TorProcessAmbiguous(String),

    #[error("Tor /proc inspection error: {0}")]
    TorInspectionError(String),

    #[error("Trusted binary resolution failed: {0}")]
    TrustedBinaryNotFound(String),

    #[error("Tor listener port {port} is closed or connection refused: {details}")]
    TorListenerPortClosed { port: u16, details: String },

    #[error("Tor listener port {port} connection timed out: {details}")]
    TorListenerTimeout { port: u16, details: String },

    #[error(
        "Tor listener port {port} belongs to wrong process (expected {expected}, found {actual})"
    )]
    TorListenerWrongProcess {
        port: u16,
        expected: String,
        actual: String,
    },

    #[error("Tor listener missing on port {port}: {details}")]
    TorListenerMissing { port: u16, details: String },

    #[error("Tor configuration fragment ownership check failed: {0}")]
    TorConfigOwnershipMismatch(String),

    #[error("Tor ControlPort authentication failed: {0}")]
    TorControlAuthFailed(String),

    #[error("Tor ControlPort protocol error: {0}")]
    TorControlProtocolError(String),

    #[error("Tor ControlPort error: {0}")]
    TorControlError(String),

    #[error("DNS protection verification failed: {0}")]
    DnsProtectionFailed(String),

    #[error("Runtime state file is corrupt or invalid: {0}")]
    RuntimeStateCorrupt(String),

    #[error("Runtime state I/O error: {0}")]
    RuntimeStateIo(String),

    #[error("Single-instance lock acquisition failed: {0}")]
    LockAcquisitionFailed(String),

    #[error("Umbra is already active or an active session exists (interface: {interface}, activation: {activation_id})")]
    AlreadyActive {
        interface: String,
        activation_id: String,
    },

    #[error("Startup transaction aborted: {0}")]
    StartupAborted(String),

    #[error("Recovery uncertain: safety invariant cannot be guaranteed, aborting to fail-closed state ({0})")]
    RecoveryUncertain(String),

    #[error("Root privileges required for operation '{0}'")]
    PrivilegeRequired(String),

    #[error("System command failed: {command}: {details}")]
    SystemCommandFailed { command: String, details: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}
