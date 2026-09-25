# Umbra

**Minimal, fail-closed Tor privacy boundary for Linux.**

Umbra is a lightweight Linux utility written in Rust that transparently routes application TCP traffic through Tor while enforcing DNS, IPv6, and direct UDP leak prevention with a kernel-level `nftables` policy.

Umbra is designed to fail closed: when Tor or a required component is unavailable, direct application Internet access is blocked rather than falling back to a direct connection.

---

## Features

- Fail-closed Tor transparent routing
- DNS leak prevention through Tor DNSPort
- IPv6 leak prevention
- Direct UDP / QUIC bypass prevention
- Default MAC randomization on supported Linux interfaces
- Explicit recovery after interrupted operation
- Dedicated Umbra-owned `nftables` policy
- Tor privilege separation
- No telemetry or external privacy-check services
- Minimal ephemeral runtime state

---

## How It Works

```text
Application
    |
    v
Umbra / nftables
    |
    +--> TCP --> Tor TransPort
    |
    +--> DNS --> Tor DNSPort
    |
    +--> IPv6 / unsupported UDP --> blocked
    |
    v
Tor
    |
    v
Internet
```

When Umbra is active, direct application egress is blocked by the kernel firewall rather than relying on the Umbra process remaining alive.

---

## Requirements

- Linux
- `nftables`
- Tor
- `iproute2`
- Rust toolchain for building from source
- systemd for optional boot-time activation

Umbra is Linux-only.

---

## Installation

### Build and install

```bash
git clone https://github.com/vivxk/Umbra.git
cd Umbra

sudo ./install.sh
```

The installation script compiles the release binary and installs the Umbra binary, Tor configuration fragment, and systemd unit.

Alternatively, install via Makefile:

```bash
make && sudo make install
```

### Tor configuration

Ensure your `/etc/tor/torrc` includes configuration fragments:

```text
%include /etc/tor/torrc.d/*.conf
```

Then enable and start Tor:

```bash
sudo systemctl enable --now tor
```

Verify:

```bash
sudo systemctl is-active tor
```

Umbra does not require a running background Umbra daemon.

> **Note (WSL2):** In WSL2 environments, Umbra automatically preserves the virtual interface MAC address because Hyper-V networking may drop frames with a randomized MAC. Use `--force-mac-randomize` to override this behavior if needed.

---

## Usage

Start Umbra:

```bash
sudo umbra start
```

Check status:

```bash
sudo umbra status
```

Request a new Tor circuit:

```bash
sudo umbra newnym
```

Stop Umbra and restore normal networking:

```bash
sudo umbra stop
```

Recover after an interrupted session:

```bash
sudo umbra recover --normal
```

Force recovery when normal recovery state is unavailable:

```bash
sudo umbra recover --force
```

Show version:

```bash
umbra version
```

---

## Boot-Time Activation

Optional boot-time activation is provided through systemd:

```bash
sudo systemctl enable --now umbra-boot.service
```

Disable it with:

```bash
sudo systemctl disable --now umbra-boot.service
```

Boot-time activation does not guarantee network isolation during every stage of early boot before Tor and Umbra have initialized.

---

## Privacy Limitations

Umbra is a network-boundary tool, not a guarantee of anonymity.

It does not protect against:

- Browser or application fingerprinting
- Account identity, cookies, or application-level identifiers
- A compromised host or local malware
- Physical observation
- Global traffic-correlation attacks
- Operating-system logging or audit mechanisms

For web anonymity, use Tor Browser and follow Tor's operational-security guidance.

---

## Uninstallation

Stop Umbra first:

```bash
sudo umbra stop
```

Then uninstall:

```bash
sudo make uninstall
```

Uninstallation refuses to proceed while Umbra is active or in an unresolved recovery state.

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
- MIT License (http://opensource.org/licenses/MIT)
