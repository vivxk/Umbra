//! Command-line interface definition using Clap.

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "umbra")]
#[command(author = "Vivek")]
#[command(version = "0.1.0")]
#[command(about = "Minimal privacy-first, fail-closed Linux network boundary", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq, Eq)]
pub enum Commands {
    /// Start Umbra privacy boundary and transparent Tor routing
    Start {
        /// Optional manual egress interface override
        #[arg(short, long)]
        interface: Option<String>,

        /// Preserve original MAC address (required in WSL2, Hyper-V, and cloud VMs with MAC anti-spoofing)
        #[arg(long)]
        no_mac_randomize: bool,
    },

    /// Stop Umbra and restore original baseline network configuration
    Stop,

    /// Query live kernel firewall, interface state, and Tor verification
    Status,

    /// Recover host from interrupted or inconsistent state to normal networking
    Recover {
        /// Reset to normal unproxied networking
        #[arg(long, conflicts_with = "force")]
        normal: bool,

        /// Force recovery when state file is missing or corrupt
        #[arg(long, conflicts_with = "normal")]
        force: bool,
    },

    /// Request a new Tor identity circuit via ControlPort
    Newnym,

    /// Display version and environment information
    Version,
}
