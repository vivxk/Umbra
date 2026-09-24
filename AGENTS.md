# AGENTS.md

## Security & Operational Guardrails

This is a security-sensitive Linux networking project.

### Absolute Invariants & Restrictions
Never:
- Flush the host nftables ruleset (`nft flush ruleset`)
- Flush iptables (`iptables -F`)
- Flush ip6tables (`ip6tables -F`)
- Destroy unrelated firewall tables
- Modify unrelated UFW, firewalld, Docker, or VPN rules
- Modify host firewall configuration outside Umbra-owned objects (`table inet umbra`)
- Run destructive network experiments on the development host
- Modify `/etc/resolv.conf` without explicit test scope
- Modify `/etc/tor/*` during development unless explicitly required
- Modify systemd networking configuration without explicit scope
- Run recursive destructive deletion against system paths
- Implement fail-open behavior (if Tor or verification fails, network remains blocked, never falling back to direct internet)
- Erase system logs or attempt anti-forensics
- Add telemetry, analytics, or external connectivity checks
- Run Tor as root

### Testing & Verification Preferences
Prefer:
- Unit tests
- Mocks
- Linux network namespaces (`ip netns`)
- Disposable Linux VMs
- Isolated test fixtures

Real privileged network tests must be isolated.
