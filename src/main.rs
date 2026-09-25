//! Main CLI entry point for Umbra.

use clap::Parser;
use std::io::{self, Write};
use std::path::Path;
use std::process;

use umbra::cli::{Cli, Commands};
use umbra::constants::{DEFAULT_TOR_CONTROLPORT, DEFAULT_TOR_DNSPORT, DEFAULT_TOR_TRANSPORT};
use umbra::error::Result;
use umbra::recovery::RecoveryController;
use umbra::system::{is_wsl_environment, require_root, ProcessLock};
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
            force_mac_randomize,
        } => handle_start(interface, no_mac_randomize, force_mac_randomize),
        Commands::Stop => handle_stop(),
        Commands::Status => handle_status(),
        Commands::Recover { normal: _, force } => handle_recover(force),
        Commands::Newnym => handle_newnym(),
        Commands::Uninstall { yes } => handle_uninstall(yes),
        Commands::Version => {
            println!("Umbra v0.1.0 - Minimal privacy-first, fail-closed Linux network boundary");
            println!("Target: Linux (nftables + Tor transparent proxying)");
            Ok(())
        }
    }
}

fn handle_start(
    interface_override: Option<String>,
    no_mac_randomize: bool,
    force_mac_randomize: bool,
) -> Result<()> {
    require_root("start")?;

    let is_wsl = is_wsl_environment();
    let should_preserve_mac = if force_mac_randomize {
        false
    } else if no_mac_randomize || is_wsl {
        if is_wsl && !no_mac_randomize {
            println!("[i] Detected WSL2 environment (Hyper-V virtual switch enforces MAC anti-spoofing).");
            println!("    Preserving baseline MAC to ensure uninterrupted network connectivity.");
        }
        true
    } else {
        false
    };

    println!("[*] Initializing Umbra privacy boundary...");

    let options = StartupTransactionOptions {
        interface_override,
        transport_port: DEFAULT_TOR_TRANSPORT,
        dns_port: DEFAULT_TOR_DNSPORT,
        state_file_override: None,
        lock_file_override: None,
        no_mac_randomize: should_preserve_mac,
    };

    let result = StartupTransaction::execute(options)?;

    println!("\n[✓] Umbra is ACTIVE");
    println!("    Interface:       {}", result.interface);
    if should_preserve_mac {
        let reason = if is_wsl {
            "WSL2 virtual interface"
        } else {
            "preserved"
        };
        println!("    MAC Address:     {} ({reason})", result.original_mac);
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

fn handle_uninstall(yes: bool) -> Result<()> {
    require_root("uninstall")?;

    println!("[*] Checking Umbra status prior to uninstallation...");

    let report = LiveVerifier::verify_current_state()?;
    if report.status != umbra::runtime_state::UmbraStatus::Inactive {
        return Err(umbra::error::UmbraError::RecoveryUncertain(format!(
            "Umbra is currently {} (or in an unrecovered state).\n\
            Uninstalling while active would leave firewall redirection rules and/or\n\
            randomized MAC settings without their restoration controller, resulting\n\
            in broken network connectivity.\n\n\
            Please restore normal networking before uninstalling:\n\
                sudo umbra stop\n\
            or (if the process crashed or recovery is required):\n\
                sudo umbra recover --normal",
            report.status
        )));
    }

    println!("[✓] Verified Umbra is INACTIVE. Proceeding with uninstallation.");

    if !yes {
        print!(
            "\n[?] Are you sure you want to uninstall Umbra and remove all configuration? [y/N]: "
        );
        io::stdout().flush().map_err(umbra::error::UmbraError::Io)?;

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(umbra::error::UmbraError::Io)?;
        let trimmed = input.trim().to_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("[*] Uninstallation cancelled.");
            return Ok(());
        }
    }

    println!("\n[*] Removing Umbra components...");

    // 1. Disable and remove systemd service unit if present
    let service_unit = Path::new("/etc/systemd/system/umbra-boot.service");
    if service_unit.exists() || service_unit.is_symlink() {
        if let Ok(mut cmd) = umbra::system::resolve_trusted_command("systemctl") {
            let _ = cmd.args(["stop", "umbra-boot.service"]).output();
            let _ = cmd.args(["disable", "umbra-boot.service"]).output();
        }
        let _ = std::fs::remove_file(service_unit);
        if let Ok(mut cmd) = umbra::system::resolve_trusted_command("systemctl") {
            let _ = cmd.args(["daemon-reload"]).output();
        }
        println!("[✓] Removed /etc/systemd/system/umbra-boot.service");
    }

    // 2. Remove Umbra-managed Tor config fragment
    let frag_path = umbra::tor::TorConfig::detect_fragment_path();
    if frag_path.exists() || frag_path.is_symlink() {
        match TorController::remove_config_fragment(&frag_path) {
            Ok(_) => {
                println!(
                    "[✓] Removed Umbra-managed Tor config fragment: {}",
                    frag_path.display()
                );
            }
            Err(e) => {
                println!(
                    "[!] Warning: Could not remove Tor fragment {}: {e}",
                    frag_path.display()
                );
            }
        }
    }

    // 3. Clean runtime directory /run/umbra
    let run_dir = Path::new(umbra::constants::RUNTIME_STATE_FILE)
        .parent()
        .unwrap_or_else(|| Path::new("/run/umbra"));
    if run_dir.exists() {
        let _ = std::fs::remove_dir_all(run_dir);
        println!("[✓] Cleaned {}", run_dir.display());
    }

    // 4. Remove symlink /usr/local/bin/umbra
    let local_bin = Path::new("/usr/local/bin/umbra");
    if local_bin.exists() || local_bin.is_symlink() {
        let _ = std::fs::remove_file(local_bin);
        println!("[✓] Removed /usr/local/bin/umbra");
    }

    // 5. Remove binary /usr/bin/umbra
    let bin = Path::new("/usr/bin/umbra");
    if bin.exists() || bin.is_symlink() {
        let _ = std::fs::remove_file(bin);
        println!("[✓] Removed /usr/bin/umbra");
    }

    println!("\n[✓] Umbra has been cleanly uninstalled from the system.");
    Ok(())
}
