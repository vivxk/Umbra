//! Main CLI entry point for Umbra.

use clap::Parser;
use std::process;

use umbra::cli::{Cli, Commands};
use umbra::constants::{DEFAULT_TOR_CONTROLPORT, DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT};
use umbra::error::{Result, UmbraError};
use umbra::firewall::{FirewallConfig, FirewallController};
use umbra::interface::InterfaceController;
use umbra::mac::MacAddress;
use umbra::recovery::RecoveryController;
use umbra::runtime_state::{ActiveState, UmbraStatus};
use umbra::system::{require_root, ProcessLock};
use umbra::tor::TorController;
use umbra::verify::LiveVerifier;

fn main() {
    let cli = Cli::parse();

    if let Err(err) = run_app(cli) {
        eprintln!("\n[!] Error: {err}");
        process::exit(1);
    }
}

fn run_app(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Start { interface } => handle_start(interface),
        Commands::Stop => handle_stop(),
        Commands::Status => handle_status(),
        Commands::Recover { normal: _ } => handle_recover(),
        Commands::Newnym => handle_newnym(),
        Commands::Version => {
            println!("Umbra v0.1.0 - Minimal privacy-first, fail-closed Linux network boundary");
            println!("Target: Linux (nftables + Tor transparent proxying)");
            Ok(())
        }
    }
}

fn handle_start(interface_override: Option<String>) -> Result<()> {
    require_root("start")?;
    let _lock = ProcessLock::acquire()?;

    println!("[*] Initializing Umbra privacy boundary...");

    // 1. Identify Egress Interface
    let iface = match interface_override {
        Some(name) => name,
        None => InterfaceController::detect_default_egress()?,
    };
    println!("[+] Authoritative egress interface: {iface}");

    // 2. Capture Baseline
    let baseline = InterfaceController::capture_baseline(&iface)?;
    println!(
        "[+] Baseline captured: MAC {} (admin UP: {})",
        baseline.original_mac, baseline.was_up
    );

    // 3. Resolve Tor Identity
    let tor_ident = TorController::find_tor_process()?;
    let tor_uid = match tor_ident {
        Some(ref ident) => {
            println!(
                "[+] Tor process verified: PID {} (UID {}, exe: {})",
                ident.pid, ident.uid, ident.exe_path
            );
            ident.uid
        }
        None => {
            let uid = TorController::resolve_tor_uid()?;
            println!("[+] Tor identity resolved: UID {uid}");
            uid
        }
    };

    // 4. Verify Tor prerequisites
    TorController::verify_transport_with_identity(DEFAULT_TOR_TRANSPORT, tor_ident.as_ref())?;
    TorController::verify_dnsport_with_identity(DEFAULT_TOR_DNSPORT, tor_ident.as_ref())?;
    println!("[+] Tor listeners verified (TransPort:{DEFAULT_TOR_TRANSPORT}, DNSPort:{DEFAULT_TOR_DNSPORT})");

    // 5. Generate and Apply Randomized MAC
    let random_mac = MacAddress::generate_random()?;
    println!("[*] Randomizing MAC for {iface} to {random_mac}...");
    InterfaceController::apply_mac(&iface, random_mac)?;
    println!("[+] MAC randomized and verified on {iface}");

    // 6. Establish Firewall Policy
    let activation_id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let fw_config = FirewallConfig {
        tor_uid,
        egress_interface: iface.clone(),
        activation_id: activation_id.clone(),
        ..Default::default()
    };

    println!("[*] Installing atomic nftables policy (table inet umbra)...");
    if let Err(e) = FirewallController::install(&fw_config) {
        eprintln!("[!] Firewall installation failed: {e}. Reverting MAC to baseline...");
        let _ = InterfaceController::restore_baseline(&baseline);
        return Err(UmbraError::FirewallInstallFailed(format!(
            "{e} (fail-closed posture preserved)"
        )));
    }
    println!("[+] Firewall policy installed and verified in kernel");

    // 7. Persist Volatile Active State
    let active_state = ActiveState::new(
        activation_id,
        iface.clone(),
        baseline.original_mac.to_string(),
        random_mac.to_string(),
        baseline.was_up,
        tor_uid,
        DEFAULT_TOR_TRANSPORT,
        DEFAULT_TOR_DNSPORT,
        fw_config.table_name,
    );
    active_state.save()?;

    // 8. Final Live Verification
    let report = LiveVerifier::verify_current_state()?;
    if report.status != UmbraStatus::Active {
        eprintln!("[!] Final verification failed. Entering fail-closed recovery state.");
        return Err(UmbraError::FirewallVerificationFailed(
            "live enforcement state failed post-activation check".to_string(),
        ));
    }

    println!("\n[✓] Umbra is ACTIVE");
    println!("    Interface:       {iface}");
    println!("    Randomized MAC:  {random_mac}");
    println!("    Firewall:        Enforced (table inet umbra)");
    println!("    Tor Routing:     Enforced (TransPort {DEFAULT_TOR_TRANSPORT})");
    println!("    DNS Intercept:   Enforced (DNSPort {DEFAULT_TOR_DNSPORT})");
    println!("    Direct Egress:   BLOCKED (fail-closed)");

    Ok(())
}

fn handle_stop() -> Result<()> {
    require_root("stop")?;
    let _lock = ProcessLock::acquire()?;

    println!("[*] Stopping Umbra and restoring network state...");
    RecoveryController::stop()?;

    println!("[✓] Umbra is INACTIVE. Normal networking restored.");
    Ok(())
}

fn handle_status() -> Result<()> {
    let report = LiveVerifier::verify_current_state()?;

    println!("Umbra Status: {}", report.status);
    if let Some(ref iface) = report.interface {
        println!("Interface:    {iface}");
    }
    if let Some(ref mac) = report.live_mac {
        println!(
            "Live MAC:     {mac} (matches state: {})",
            report.mac_matches_state
        );
    }
    println!(
        "Firewall:     {}",
        if report.firewall_ok {
            "verified"
        } else {
            "not active"
        }
    );
    println!(
        "Tor Process:  {}",
        if report.tor_process_ok {
            "verified"
        } else {
            "not detected"
        }
    );
    println!(
        "TransPort:    {}",
        if report.transport_ok {
            "verified"
        } else {
            "not listening"
        }
    );
    println!(
        "DNSPort:      {}",
        if report.dnsport_ok {
            "verified"
        } else {
            "not listening"
        }
    );
    println!(
        "ControlPort:  {}",
        if report.controlport_ok {
            "verified"
        } else {
            "not listening / unverified"
        }
    );

    println!("\nDiagnostics:");
    for detail in &report.details {
        println!(" - {detail}");
    }

    Ok(())
}

fn handle_recover() -> Result<()> {
    require_root("recover")?;
    let _lock = ProcessLock::acquire()?;

    println!("[*] Executing normal recovery workflow...");
    let actions = RecoveryController::recover_normal()?;

    println!("[✓] Recovery completed:");
    for action in actions {
        println!(" - {action}");
    }

    Ok(())
}

fn handle_newnym() -> Result<()> {
    require_root("newnym")?;
    let _lock = ProcessLock::acquire()?;
    println!("[*] Requesting new Tor identity (SIGNAL NEWNYM)...");
    TorController::request_newnym(DEFAULT_TOR_CONTROLPORT)?;
    println!("[✓] Successfully signaled Tor for new identity circuit.");
    Ok(())
}
