//! Main CLI entry point for Umbra.

use clap::Parser;
use std::process;

use umbra::cli::{Cli, Commands};
use umbra::constants::{DEFAULT_TOR_CONTROLPORT, DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT};
use umbra::error::Result;
use umbra::recovery::RecoveryController;
use umbra::system::{require_root, ProcessLock};
use umbra::tor::TorController;
use umbra::transaction::{StartupTransaction, StartupTransactionOptions};
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
        Commands::Start {
            interface,
            no_mac_randomize,
        } => handle_start(interface, no_mac_randomize),
        Commands::Stop => handle_stop(),
        Commands::Status => handle_status(),
        Commands::Recover { normal: _, force } => handle_recover(force),
        Commands::Newnym => handle_newnym(),
        Commands::Version => {
            println!("Umbra v0.1.0 - Minimal privacy-first, fail-closed Linux network boundary");
            println!("Target: Linux (nftables + Tor transparent proxying)");
            Ok(())
        }
    }
}

fn handle_start(interface_override: Option<String>, no_mac_randomize: bool) -> Result<()> {
    require_root("start")?;

    println!("[*] Initializing Umbra privacy boundary...");

    let options = StartupTransactionOptions {
        interface_override,
        transport_port: DEFAULT_TOR_TRANSPORT,
        dns_port: DEFAULT_TOR_DNSPORT,
        state_file_override: None,
        lock_file_override: None,
        no_mac_randomize,
    };

    let result = StartupTransaction::execute(options)?;

    println!("\n[✓] Umbra is ACTIVE");
    println!("    Interface:       {}", result.interface);
    if no_mac_randomize {
        println!("    MAC Address:     {} (preserved)", result.original_mac);
    } else {
        println!("    Randomized MAC:  {}", result.randomized_mac);
    }
    println!("    Firewall:        Enforced (table inet umbra)");
    println!(
        "    Tor Routing:     Enforced (TransPort {})",
        result.transport_port
    );
    println!(
        "    DNS Intercept:   Enforced (DNSPort {})",
        result.dns_port
    );
    println!("    Direct Egress:   BLOCKED (fail-closed)");

    Ok(())
}

fn handle_stop() -> Result<()> {
    require_root("stop")?;

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

fn handle_recover(force: bool) -> Result<()> {
    require_root("recover")?;

    let actions = if force {
        println!("[*] Executing force recovery workflow...");
        RecoveryController::recover_force()?
    } else {
        println!("[*] Executing normal recovery workflow...");
        RecoveryController::recover_normal()?
    };

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
