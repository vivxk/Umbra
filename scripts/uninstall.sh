#!/usr/bin/env bash
set -euo pipefail

# Umbra Uninstallation Script
# Strictly verifies Umbra is INACTIVE before removal (refusing to uninstall if active,
# per Section 89 of Umbra specification). Cleans only Umbra-owned config fragments
# and files after verifying ownership markers.
# Supports DESTDIR and PREFIX for packagers and isolated testing.

DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/usr}"
BIN_DIR="${DESTDIR}${PREFIX}/bin"
LOCAL_BIN_DIR="${DESTDIR}/usr/local/bin"
SYSCONFDIR="${DESTDIR}/etc"
TORRC_DIR="${SYSCONFDIR}/tor/torrc.d"
TOR_FRAGMENT="${TORRC_DIR}/umbra.conf"
SYSTEMD_DIR="${SYSCONFDIR}/systemd/system"
RUN_DIR="${DESTDIR}/run/umbra"

if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: Uninstallation requires root privileges. Please run with sudo:"
    echo "    sudo bash scripts/uninstall.sh"
    exit 1
fi

echo "[*] Checking Umbra status prior to uninstallation..."

# Section 89 Requirement: Verify that Umbra is NOT active before removal.
IS_ACTIVE=0

# Check 1: Live runtime state file (/run/umbra/active.json per Section 9 & Section 89)
if [ -f "$RUN_DIR/active.json" ] || [ -f "$RUN_DIR/state.json" ]; then
    echo "[!] Detected active runtime state file in $RUN_DIR"
    IS_ACTIVE=1
fi
if [ -z "$DESTDIR" ] && { [ -f "/run/umbra/active.json" ] || [ -f "/run/umbra/state.json" ]; }; then
    echo "[!] Detected active runtime state file in /run/umbra"
    IS_ACTIVE=1
fi

# Check 2: Live kernel nftables table
if [ -z "$DESTDIR" ] && command -v nft >/dev/null 2>&1; then
    if nft list table inet umbra >/dev/null 2>&1; then
        echo "[!] Detected active kernel firewall table 'table inet umbra'"
        IS_ACTIVE=1
    fi
fi

# Check 3: CLI status verification if binary is installed
UMBRA_BIN=""
if [ -x "$BIN_DIR/umbra" ]; then
    UMBRA_BIN="$BIN_DIR/umbra"
elif [ -x "$LOCAL_BIN_DIR/umbra" ]; then
    UMBRA_BIN="$LOCAL_BIN_DIR/umbra"
elif [ -x "/usr/bin/umbra" ]; then
    UMBRA_BIN="/usr/bin/umbra"
elif command -v umbra >/dev/null 2>&1; then
    UMBRA_BIN="$(command -v umbra)"
fi

if [ -n "$UMBRA_BIN" ] && [ -z "$DESTDIR" ]; then
    STATUS_OUT="$("$UMBRA_BIN" status 2>&1 || true)"
    if echo "$STATUS_OUT" | grep -q -E "ACTIVE|RECOVERY_REQUIRED|UNKNOWN"; then
        echo "[!] CLI reports Umbra is not inactive:"
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
if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled umbra-boot.service >/dev/null 2>&1; then
        echo "[*] Disabling systemd service umbra-boot.service..."
        systemctl disable umbra-boot.service 2>/dev/null || true
    fi
    if systemctl is-active umbra-boot.service >/dev/null 2>&1; then
        echo "[*] Stopping systemd service umbra-boot.service..."
        systemctl stop umbra-boot.service 2>/dev/null || true
    fi
fi

if [ -f "$SYSTEMD_DIR/umbra-boot.service" ]; then
    rm -f "$SYSTEMD_DIR/umbra-boot.service"
    if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
    fi
    echo "[✓] Removed $SYSTEMD_DIR/umbra-boot.service"
fi

# 2. Clean Tor configuration fragment after verifying ownership marker
if [ -f "$TOR_FRAGMENT" ]; then
    if grep -q "# umbra-managed" "$TOR_FRAGMENT"; then
        rm -f "$TOR_FRAGMENT"
        echo "[✓] Removed Umbra-managed Tor config fragment: $TOR_FRAGMENT"
        rmdir "$TORRC_DIR" 2>/dev/null || true
    else
        echo "[!] Warning: $TOR_FRAGMENT exists but does NOT contain '# umbra-managed' marker."
        echo "    Leaving file untouched to prevent deleting user configuration."
    fi
fi

# 3. Remove installed binaries and symlinks
if [ -f "$BIN_DIR/umbra" ] || [ -L "$BIN_DIR/umbra" ]; then
    rm -f "$BIN_DIR/umbra"
    echo "[✓] Removed $BIN_DIR/umbra"
fi

if [ -L "$LOCAL_BIN_DIR/umbra" ] || [ -f "$LOCAL_BIN_DIR/umbra" ]; then
    rm -f "$LOCAL_BIN_DIR/umbra"
    echo "[✓] Removed $LOCAL_BIN_DIR/umbra"
fi

# 4. Clean runtime directory
if [ -d "$RUN_DIR" ]; then
    rm -rf "$RUN_DIR"
    echo "[✓] Cleaned $RUN_DIR"
fi
if [ -z "$DESTDIR" ] && [ -d "/run/umbra" ]; then
    rm -rf "/run/umbra"
    echo "[✓] Cleaned /run/umbra"
fi

echo ""
echo "[✓] Umbra has been cleanly uninstalled from the system."
