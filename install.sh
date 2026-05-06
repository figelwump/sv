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

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

linux_install_hint() {
  if has_cmd apt-get; then
    printf "Install with: sudo apt install -y pass gnupg pinentry-curses. After sv is installed, run: sv doctor"
  else
    printf "Install pass, gnupg, and a pinentry program for your Linux distro. After sv is installed, run: sv doctor"
  fi
}

OS="$(uname -s)"

linux_pinentry_ready() {
  has_cmd pinentry || has_cmd pinentry-curses
}

linux_install_deps() {
  local installer=()

  if [[ "${EUID}" -eq 0 ]]; then
    installer=(apt-get)
  elif has_cmd sudo; then
    installer=(sudo apt-get)
  else
    die "Linux dependencies are missing and sudo is not available. $(linux_install_hint)"
  fi

  note "installing Linux dependencies: pass gnupg pinentry-curses"
  note "running: ${installer[*]} install -y pass gnupg pinentry-curses"
  "${installer[@]}" install -y pass gnupg pinentry-curses \
    || die "failed to install Linux dependencies. $(linux_install_hint)"
}

linux_prepare_runtime() {
  local missing=()

  has_cmd pass || missing+=("pass")
  has_cmd gpg || missing+=("gpg")
  linux_pinentry_ready || missing+=("pinentry")

  if [[ ${#missing[@]} -eq 0 ]]; then
    return
  fi

  if has_cmd apt-get; then
    linux_install_deps
  else
    die "missing Linux dependencies: ${missing[*]}. $(linux_install_hint)"
  fi

  has_cmd pass || die "pass is required on Linux. $(linux_install_hint)"
  has_cmd gpg || die "gpg is required on Linux. $(linux_install_hint)"
  linux_pinentry_ready || die "a pinentry program is required on Linux. $(linux_install_hint)"
}

case "${OS}" in
  Darwin)
    has_cmd security || die "macOS security command not found"
    ;;
  Linux)
    linux_prepare_runtime
    ;;
  *)
    die "sv only supports macOS and Linux"
    ;;
esac

has_cmd curl || die "curl is required"

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

chmod 755 "$tmp"

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

if [[ "${OS}" == "Linux" ]]; then
  printf "Run 'sv doctor' to verify your Linux setup.\n"

  if [[ ! -f "${PASSWORD_STORE_DIR:-$HOME/.password-store}/.gpg-id" ]]; then
    note "password-store is not initialized yet."
    note "Run 'pass init <gpg-id>' before using sv."
  fi
fi
