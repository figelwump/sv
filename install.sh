#!/usr/bin/env bash
#
# Install sv — simple secret vault
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/figelwump/sv/main/install.sh | bash
#

set -euo pipefail

REPO="figelwump/sv"
RAW_URL="https://raw.githubusercontent.com/${REPO}/main/sv"
INSTALL_DIR="/usr/local/bin"
INSTALL_PATH="${INSTALL_DIR}/sv"

die() {
  printf "sv-install: %s\n" "$*" >&2
  exit 1
}

# Check macOS
[[ "$(uname -s)" == "Darwin" ]] || die "sv only supports macOS"

# Check for security CLI
command -v security >/dev/null 2>&1 || die "macOS security command not found"

# Check curl
command -v curl >/dev/null 2>&1 || die "curl is required"

# Download
printf "Downloading sv from %s ...\n" "${RAW_URL}"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if ! curl -fsSL "${RAW_URL}" -o "$tmp"; then
  die "download failed"
fi

# Sanity check
if ! head -1 "$tmp" | grep -q '^#!/'; then
  die "downloaded file doesn't look like a script — aborting"
fi

chmod +x "$tmp"

# Install (may need sudo)
if [[ -w "${INSTALL_DIR}" ]]; then
  mv "$tmp" "${INSTALL_PATH}"
else
  printf "Need sudo to write to %s\n" "${INSTALL_DIR}"
  sudo mv "$tmp" "${INSTALL_PATH}"
fi
trap - EXIT

printf "sv installed to %s\n" "${INSTALL_PATH}"
printf "Run 'sv help' to get started.\n"
