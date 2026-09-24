#!/usr/bin/env bash
set -euo pipefail

# Umbra Uninstallation Script
# Strictly verifies Umbra is INACTIVE before removal (refusing to uninstall if active,
# per Section 89 of Umbra specification). Cleans only Umbra-owned config fragments
# and files after verifying ownership markers.

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: Uninstallation requires root privileges. Please run with sudo:"
    echo "    sudo bash scripts/uninstall.sh"
    exit 1
fi

echo "[*] Checking Umbra status prior to uninstallation..."

# Section 89 Requirement: Verify that Umbra is NOT active before removal.
IS_ACTIVE=0

# Check 1: Live runtime state file
if [ -f /run/umbra/state.json ]; then
    echo "[!] Detected active runtime state file at /run/umbra/state.json"
    IS_ACTIVE=1
fi

# Check 2: Live kernel nftables table
if command -v nft >/dev/null 2>&1; then
    if nft list table inet umbra >/dev/null 2>&1; then
        echo "[!] Detected active kernel firewall table 'table inet umbra'"
        IS_ACTIVE=1
    fi
fi

# Check 3: CLI status verification if binary is installed
if [ -x /usr/bin/umbra ]; then
    STATUS_OUT="$(/usr/bin/umbra status 2>&1 || true)"
    if echo "$STATUS_OUT" | grep -q -E "Status: ACTIVE|Status: RECOVERY_REQUIRED"; then
        echo "[!] CLI reports Umbra is ACTIVE or in RECOVERY_REQUIRED state:"
        echo "$STATUS_OUT" | sed 's/^/    /'
        IS_ACTIVE=1
    fi
fi

if [ "$IS_ACTIVE" -eq 1 ]; then
    echo ""
    echo "[!] REFUSING TO UNINSTALL: Umbra is currently ACTIVE or in an unrecovered state."
    echo "    Uninstalling while active would leave firewall redirection rules and/or"
    echo "    randomized MAC settings without their restoration controller, resulting"
    echo "    in broken network connectivity."
    echo ""
    echo "    Please restore normal networking before uninstalling:"
    echo "        sudo umbra stop"
    echo "    or (if the process crashed or recovery is required):"
    echo "        sudo umbra recover --normal"
    echo ""
    exit 1
fi

echo "[✓] Verified Umbra is INACTIVE. Proceeding with uninstallation."

# 1. Disable and remove systemd boot service if present
if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled umbra-boot.service >/dev/null 2>&1; then
        echo "[*] Disabling systemd service umbra-boot.service..."
        systemctl disable umbra-boot.service 2>/dev/null || true
    fi
    if systemctl is-active umbra-boot.service >/dev/null 2>&1; then
        echo "[*] Stopping systemd service umbra-boot.service..."
        systemctl stop umbra-boot.service 2>/dev/null || true
    fi
fi

if [ -f /etc/systemd/system/umbra-boot.service ]; then
    rm -f /etc/systemd/system/umbra-boot.service
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
    echo "[✓] Removed /etc/systemd/system/umbra-boot.service"
fi

# 2. Clean Tor configuration fragment after verifying ownership marker
TOR_FRAGMENT="/etc/tor/torrc.d/umbra.conf"
if [ -f "$TOR_FRAGMENT" ]; then
    if grep -q "# umbra-managed" "$TOR_FRAGMENT"; then
        rm -f "$TOR_FRAGMENT"
        echo "[✓] Removed Umbra-managed Tor config fragment: $TOR_FRAGMENT"
        rmdir /etc/tor/torrc.d 2>/dev/null || true
    else
        echo "[!] Warning: $TOR_FRAGMENT exists but does NOT contain '# umbra-managed' marker."
        echo "    Leaving file untouched to prevent deleting user configuration."
    fi
fi

# 3. Remove installed binaries and symlinks
if [ -f /usr/bin/umbra ] || [ -L /usr/bin/umbra ]; then
    rm -f /usr/bin/umbra
    echo "[✓] Removed /usr/bin/umbra"
fi

if [ -L /usr/local/bin/umbra ] || [ -f /usr/local/bin/umbra ]; then
    rm -f /usr/local/bin/umbra
    echo "[✓] Removed /usr/local/bin/umbra"
fi

# 4. Clean runtime directory
if [ -d /run/umbra ]; then
    rm -rf /run/umbra
    echo "[✓] Cleaned /run/umbra"
fi

echo ""
echo "[✓] Umbra has been cleanly uninstalled from the system."
