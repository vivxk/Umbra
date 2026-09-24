# Umbra

**Minimal Privacy-First, Fail-Closed Linux Network Boundary**

Umbra is a lightweight Linux utility written in Rust that enforces transparent Tor routing, DNS leak prevention, IPv6 blocking, and egress interface MAC randomization.

## Core Properties

- **Small & Auditable**: Clean-room implementation in safe Rust with minimal dependencies.
- **Fail-Closed**: Blocks egress traffic rather than leaking direct internet connections if Tor is disrupted.
- **Kernel-Enforced**: Policy resides in Linux `nftables` (`table inet umbra`); process termination does not disrupt protection.
- **Isolated State**: Runtime state is stored transiently in `/run/umbra/` and cleared on reboot; no persistent session databases.
- **Zero Telemetry**: Performs zero outbound diagnostic requests or external IP queries.

## Architecture

```text
Application Traffic
        │
        ▼ (nftables: table inet umbra)
   Redirected / Controlled
        │
   ┌────┴──────────────────────────┐
   │                               │
   ▼ (TCP)                         ▼ (DNS UDP 53)
Tor TransPort (127.0.0.1:9040)  Tor DNSPort (127.0.0.1:5353)
   │                               │
   └───────────────┬───────────────┘
                   ▼
              Tor Network
                   │
                   ▼
                Internet
```

## CLI Usage

```bash
# Start privacy routing (fail-closed)
sudo umbra start

# Stop privacy routing and restore original baseline
sudo umbra stop

# Inspect live verification state
sudo umbra status

# Recover normal networking after unexpected interruption
sudo umbra recover --normal

# Request a new Tor identity circuit
sudo umbra newnym

# Print version
umbra version
```
