# Security Policy: Umbra

## Threat Model & Security Posture

Umbra is a lightweight Linux network-boundary controller designed to enforce transparent Tor routing with a strict fail-closed security model.

### Core Security Invariants
1. **No Direct Internet Fallback**: Normal application traffic is strictly directed through Tor. If Tor is unavailable, network egress is dropped.
2. **Crash Resilience**: Network protections are enforced in the Linux kernel via `nftables`. If the `umbra` process crashes or terminates abruptly, the firewall state remains active in the kernel, preserving fail-closed isolation.
3. **Explicit Human Recovery**: Recovery to normal unproxied networking is only performed upon explicit user invocation (`sudo umbra recover --normal` or `sudo umbra stop`). Automatic fail-open watchdogs are intentionally prohibited.
4. **Isolated Firewall Ownership**: Umbra exclusively manipulates its own dedicated table (`inet umbra`). It verifies ownership markers and never flushes global rulesets or interferes with unrelated tables (e.g. UFW, firewalld, Docker, VPNs).
5. **Privilege Separation**: Umbra runs with elevated privileges only to manage network links and kernel firewall tables. Tor must run under its own unprivileged dedicated system account (e.g., `debian-tor`).
6. **DNS & Leak Prevention**: All outbound DNS traffic is intercepted and directed to Tor's DNSPort. Direct external UDP/TCP DNS, IPv6 traffic, and QUIC (UDP/443) bypass paths are blocked.
7. **No Telemetry or Remote Calls**: Umbra conducts all operational verifications locally. It never calls external IP reflection or diagnostic services.

### Privacy Limitations (Explicit Disclosure)
Umbra enforces network layer routing, DNS restrictions, IPv6 blocks, and MAC randomization. It does **not** protect against:
- Application-level identifiers, browser cookies, and fingerprinting
- Account authentication identities
- Entry guard / ISP correlation attacks
- Physical or host-level compromise / local malware
- OS audit logs and journald traces (Umbra is not an anti-forensics tool)
