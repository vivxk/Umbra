#!/usr/bin/env bash
set -euo pipefail

# Umbra Root Installation Wrapper
# Facilitates direct installation via: sudo ./install.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$SCRIPT_DIR/scripts/install.sh" "$@"
