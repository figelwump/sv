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

note() {
  printf "sv-install: %s\n" "$*" >&2
}

linux_install_hint() {
  if command -v apt-get >/dev/null 2>&1; then
    printf "Install with: sudo apt install -y pass gnupg pinentry-curses. Then re-run this installer. After sv is installed, run: sv doctor"
  else
    printf "Install pass, gnupg, and a pinentry program for your Linux distro. Then re-run this installer. After sv is installed, run: sv doctor"
  fi
}

OS="$(uname -s)"

case "${OS}" in
  Darwin)
    command -v security >/dev/null 2>&1 || die "macOS security command not found"
    ;;
  Linux)
    command -v pass >/dev/null 2>&1 || die "pass is required on Linux. $(linux_install_hint)"
    command -v gpg >/dev/null 2>&1 || die "gpg is required on Linux. $(linux_install_hint)"
    ;;
  *)
    die "sv only supports macOS and Linux"
    ;;
esac

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

if [[ "${OS}" == "Linux" && ! -f "${PASSWORD_STORE_DIR:-$HOME/.password-store}/.gpg-id" ]]; then
  note "password-store is not initialized yet."
  note "Run 'pass init <gpg-id>' before using sv."
fi
