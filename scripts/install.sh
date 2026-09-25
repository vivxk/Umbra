#!/usr/bin/env bash
set -euo pipefail

# Umbra Installation Script
# Installs release binary to /usr/bin/umbra, installs managed Tor config fragment to
# /etc/tor/torrc.d/umbra.conf, and installs systemd boot service unit template.
# Supports DESTDIR and PREFIX for packagers and isolated testing.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

DESTDIR="${DESTDIR:-}"
PREFIX="${PREFIX:-/usr}"
BIN_DIR="${DESTDIR}${PREFIX}/bin"
LOCAL_BIN_DIR="${DESTDIR}/usr/local/bin"
SYSCONFDIR="${DESTDIR}/etc"
TORRC_DIR="${SYSCONFDIR}/tor/torrc.d"
TOR_FRAGMENT="${TORRC_DIR}/umbra.conf"
SYSTEMD_DIR="${SYSCONFDIR}/systemd/system"

if [ -z "$DESTDIR" ] && [ "$(id -u)" -ne 0 ]; then
    echo "[!] Error: Installation requires root privileges. Please run with sudo:"
    echo "    sudo ./install.sh"
    exit 1
fi

echo "[*] Installing Umbra Privacy Boundary..."

# 1. Locate or compile the release binary
RELEASE_BIN="$REPO_ROOT/target/release/umbra"
if [ ! -f "$RELEASE_BIN" ]; then
    # If debug binary exists in test/development environments and release is absent, use it if DESTDIR is set
    if [ -n "$DESTDIR" ] && [ -f "$REPO_ROOT/target/debug/umbra" ]; then
        RELEASE_BIN="$REPO_ROOT/target/debug/umbra"
    else
        # FIX #10: Root must never compile cargo build artifacts directly
        if [ "$(id -u)" -eq 0 ] && [ -z "${SUDO_USER:-}" ]; then
            echo "[!] Error: Release binary not found at $RELEASE_BIN. Building cargo artifacts as root is not permitted."
            echo "    Please build the binary as a normal user first:"
            echo "        make"
            echo "    Then run installation as root:"
            echo "        sudo make install"
            exit 1
        fi

        echo "[*] Release binary not found at $RELEASE_BIN. Attempting build with cargo..."
        CARGO_BIN="$(command -v cargo || true)"
        if [ -z "$CARGO_BIN" ] && [ -n "${SUDO_USER:-}" ]; then
            USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
            if [ -x "$USER_HOME/.cargo/bin/cargo" ]; then
                CARGO_BIN="$USER_HOME/.cargo/bin/cargo"
            fi
        fi

        if [ -z "$CARGO_BIN" ]; then
            echo "[!] Error: 'cargo' binary not found. Please compile the release binary first:"
            echo "    make (or cargo build --release)"
            exit 1
        fi

        echo "[*] Compiling release binary with $CARGO_BIN..."
        if [ -n "${SUDO_USER:-}" ]; then
            sudo -u "$SUDO_USER" "$CARGO_BIN" build --release --manifest-path "$REPO_ROOT/Cargo.toml"
        else
            "$CARGO_BIN" build --release --manifest-path "$REPO_ROOT/Cargo.toml"
        fi
    fi
fi

if [ ! -f "$RELEASE_BIN" ]; then
    echo "[!] Error: Failed to find compiled binary at $RELEASE_BIN"
    exit 1
fi

# 2. Install binary to $BIN_DIR/umbra and symlink $LOCAL_BIN_DIR/umbra
echo "[*] Installing binary to $BIN_DIR/umbra..."
if [ -e "$BIN_DIR/umbra" ] || [ -L "$BIN_DIR/umbra" ]; then
    if [ -L "$BIN_DIR/umbra" ]; then
        echo "[!] Error: Existing file at $BIN_DIR/umbra is a symbolic link."
        echo "    Refusing to overwrite symlink to prevent configuration tampering."
        exit 1
    fi
    if [ ! -f "$BIN_DIR/umbra" ]; then
        echo "[!] Error: Existing object at $BIN_DIR/umbra is not a regular file."
        echo "    Refusing to overwrite non-regular file."
        exit 1
    fi
    if ! "$BIN_DIR/umbra" version 2>/dev/null | grep -qi "umbra" && ! strings "$BIN_DIR/umbra" 2>/dev/null | grep -q "table inet umbra"; then
        echo "[!] Error: Existing file at $BIN_DIR/umbra does not appear to be an Umbra binary."
        echo "    Refusing to overwrite unverified binary to prevent destroying unrelated files."
        exit 1
    fi
    if [ -z "$DESTDIR" ]; then
        BIN_OWNER="$(stat -c '%u' "$BIN_DIR/umbra" 2>/dev/null || stat -f '%u' "$BIN_DIR/umbra" 2>/dev/null || true)"
        if [ -n "$BIN_OWNER" ] && [ "$BIN_OWNER" -ne 0 ]; then
            echo "[!] Error: Existing file at $BIN_DIR/umbra is not owned by root (UID 0)."
            echo "    Refusing to overwrite non-root binary."
            exit 1
        fi
    fi
fi
mkdir -p "$BIN_DIR"
install -m 0755 "$RELEASE_BIN" "$BIN_DIR/umbra"

if [ "$BIN_DIR" != "$LOCAL_BIN_DIR" ] && [ "$(realpath "$BIN_DIR" 2>/dev/null || echo "$BIN_DIR")" != "$(realpath "$LOCAL_BIN_DIR" 2>/dev/null || echo "$LOCAL_BIN_DIR")" ]; then
    if [ -e "$LOCAL_BIN_DIR/umbra" ] || [ -L "$LOCAL_BIN_DIR/umbra" ]; then
        if [ ! -L "$LOCAL_BIN_DIR/umbra" ]; then
            echo "[!] Error: $LOCAL_BIN_DIR/umbra exists and is not a symbolic link."
            echo "    Refusing to overwrite regular file to prevent destroying unrelated files."
            exit 1
        fi
        LINK_TARGET="$(readlink "$LOCAL_BIN_DIR/umbra" || true)"
        if [ "$LINK_TARGET" != "$PREFIX/bin/umbra" ] && [ "$LINK_TARGET" != "/usr/bin/umbra" ] && [ "$LINK_TARGET" != "umbra" ]; then
            echo "[!] Error: Existing symlink at $LOCAL_BIN_DIR/umbra points to '$LINK_TARGET' (expected '$PREFIX/bin/umbra')."
            echo "    Refusing to overwrite unexpected symlink."
            exit 1
        fi
    fi
    mkdir -p "$LOCAL_BIN_DIR"
    ln -sf "$PREFIX/bin/umbra" "$LOCAL_BIN_DIR/umbra"
    echo "[✓] Symlinked: $LOCAL_BIN_DIR/umbra -> $PREFIX/bin/umbra"
fi
echo "[✓] Binary installed: $BIN_DIR/umbra"

# 3. Install Tor configuration fragment with verified ownership and directory security
if [ -e "$TORRC_DIR" ]; then
    if [ -L "$TORRC_DIR" ]; then
        echo "[!] Error: $TORRC_DIR is a symbolic link. Refusing to install."
        exit 1
    fi
    if [ ! -d "$TORRC_DIR" ]; then
        echo "[!] Error: $TORRC_DIR is not a directory. Refusing to install."
        exit 1
    fi
    if [ -z "$DESTDIR" ]; then
        DIR_OWNER="$(stat -c '%u' "$TORRC_DIR" 2>/dev/null || stat -f '%u' "$TORRC_DIR" 2>/dev/null || true)"
        if [ -n "$DIR_OWNER" ] && [ "$DIR_OWNER" -ne 0 ]; then
            echo "[!] Error: $TORRC_DIR is not owned by root (UID 0)."
            echo "    Refusing to install into non-root directory."
            exit 1
        fi
    fi
    PERMS="$(stat -c '%a' "$TORRC_DIR" 2>/dev/null || stat -f '%Lp' "$TORRC_DIR" 2>/dev/null || true)"
    if [ -n "$PERMS" ]; then
        if echo "$PERMS" | grep -q -E "[2367].$|.[2367]$"; then
            echo "[!] Error: $TORRC_DIR has insecure permissions ($PERMS: group or world-writable)."
            echo "    Refusing to install into insecure directory."
            exit 1
        fi
    fi
else
    mkdir -p "$TORRC_DIR"
    chmod 0755 "$TORRC_DIR"
fi

if [ -L "$TOR_FRAGMENT" ]; then
    echo "[!] Error: Existing file at $TOR_FRAGMENT is a symbolic link."
    echo "    Refusing to overwrite symlink to prevent configuration tampering or privilege abuse."
    exit 1
fi

if [ -e "$TOR_FRAGMENT" ]; then
    if [ ! -f "$TOR_FRAGMENT" ]; then
        echo "[!] Error: Existing object at $TOR_FRAGMENT is not a regular file. Refusing to overwrite."
        exit 1
    fi
    if ! grep -q "# umbra-managed" "$TOR_FRAGMENT"; then
        echo "[!] Error: Existing file at $TOR_FRAGMENT is not managed by Umbra (missing '# umbra-managed' marker)."
        echo "    Refusing to overwrite unmanaged file to prevent configuration corruption."
        exit 1
    fi
    if [ -z "$DESTDIR" ]; then
        FRAG_OWNER="$(stat -c '%u' "$TOR_FRAGMENT" 2>/dev/null || stat -f '%u' "$TOR_FRAGMENT" 2>/dev/null || true)"
        if [ -n "$FRAG_OWNER" ] && [ "$FRAG_OWNER" -ne 0 ]; then
            echo "[!] Error: Existing fragment at $TOR_FRAGMENT is not owned by root (UID 0). Refusing to overwrite."
            exit 1
        fi
    fi
    if ! grep -q "TransPort 127.0.0.1:9040" "$TOR_FRAGMENT" || ! grep -q "DNSPort 127.0.0.1:5353" "$TOR_FRAGMENT"; then
        echo "[!] Error: Existing fragment at $TOR_FRAGMENT contains '# umbra-managed' but has been modified by the administrator."
        echo "    Refusing to silently overwrite modified configuration file."
        exit 1
    fi
    echo "[*] Updating existing Umbra-managed fragment at $TOR_FRAGMENT..."
fi

TMP_FRAGMENT="${TOR_FRAGMENT}.tmp.$$"
cat > "$TMP_FRAGMENT" <<'EOF'
# umbra-managed: Umbra Tor Configuration Fragment
# Generated automatically by Umbra privacy boundary. Do not edit directly.
TransPort 127.0.0.1:9040
DNSPort 127.0.0.1:5353
ControlPort 127.0.0.1:9051
CookieAuthentication 1
EOF

chmod 0644 "$TMP_FRAGMENT"
mv -f "$TMP_FRAGMENT" "$TOR_FRAGMENT"
echo "[✓] Tor configuration fragment installed at $TOR_FRAGMENT"

if [ -z "$DESTDIR" ] && [ -f /etc/tor/torrc ]; then
    if ! grep -q -E "%include /etc/tor/torrc\.d" /etc/tor/torrc; then
        echo "[i] Reminder: Please verify that '/etc/tor/torrc' contains:"
        echo "    %include /etc/tor/torrc.d/*.conf"
        echo "    Then reload Tor: sudo systemctl restart tor"
    fi
fi

# 4. Install systemd boot service unit template if systemd is present
SERVICE_SRC="$REPO_ROOT/systemd/umbra-boot.service"
if [ -f "$SERVICE_SRC" ]; then
    if [ -e "$SYSTEMD_DIR/umbra-boot.service" ] || [ -L "$SYSTEMD_DIR/umbra-boot.service" ]; then
        if [ -L "$SYSTEMD_DIR/umbra-boot.service" ]; then
            echo "[!] Error: Existing file at $SYSTEMD_DIR/umbra-boot.service is a symbolic link."
            echo "    Refusing to overwrite symlink."
            exit 1
        fi
        if [ ! -f "$SYSTEMD_DIR/umbra-boot.service" ]; then
            echo "[!] Error: Existing object at $SYSTEMD_DIR/umbra-boot.service is not a regular file."
            echo "    Refusing to overwrite non-regular file."
            exit 1
        fi
        if ! grep -q "umbra" "$SYSTEMD_DIR/umbra-boot.service"; then
            echo "[!] Error: Existing file at $SYSTEMD_DIR/umbra-boot.service is not an Umbra unit."
            echo "    Refusing to overwrite unmanaged service file."
            exit 1
        fi
        if [ -z "$DESTDIR" ]; then
            UNIT_OWNER="$(stat -c '%u' "$SYSTEMD_DIR/umbra-boot.service" 2>/dev/null || stat -f '%u' "$SYSTEMD_DIR/umbra-boot.service" 2>/dev/null || true)"
            if [ -n "$UNIT_OWNER" ] && [ "$UNIT_OWNER" -ne 0 ]; then
                echo "[!] Error: Existing file at $SYSTEMD_DIR/umbra-boot.service is not owned by root (UID 0)."
                echo "    Refusing to overwrite non-root service file."
                exit 1
            fi
        fi
    fi
    mkdir -p "$SYSTEMD_DIR"
    install -m 0644 "$SERVICE_SRC" "$SYSTEMD_DIR/umbra-boot.service"
    echo "[✓] Systemd unit installed: $SYSTEMD_DIR/umbra-boot.service"
    if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
    fi
    if [ -z "$DESTDIR" ]; then
        echo "[i] Optional: Enable boot-time fail-closed enforcement with:"
        echo "    sudo systemctl enable umbra-boot.service"
    fi
fi

echo ""
echo "[✓] Umbra installation completed successfully."
echo "    Start routing:  sudo umbra start"
echo "    Check status:   sudo umbra status"
echo "    Stop routing:   sudo umbra stop"
echo "    Uninstall:      sudo make uninstall"
