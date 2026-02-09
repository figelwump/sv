#!/usr/bin/env bash
#
# sv — simple secret vault for local dev
#
# Stores secrets in macOS Keychain. Injects them into processes on demand.
# Never stores values in files. Never prints values unless explicitly asked.
#
# Usage:
#   sv set <KEY>               Store a secret (prompts or reads stdin)
#   sv get <KEY>               Print a secret value (interactive TTY only)
#   sv rm <KEY>                Delete a secret
#   sv ls                      List secret names (never values)
#   sv exec -- <cmd> [args]    Run a command with secrets as env vars
#   sv help                    Show this help
#

set -euo pipefail

readonly SV_SERVICE_PREFIX="sv:"
readonly SV_KEYCHAIN_ACCOUNT="${USER}"
readonly SV_MANIFEST=".secrets"

# ─── Helpers ───────────────────────────────────────────────────────────────────

die() {
  printf "sv: %s\n" "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

# ─── Keychain operations ──────────────────────────────────────────────────────

# Store a secret in the Keychain.
# Uses -U to update if it already exists.
kc_set() {
  local key="$1" value="$2"
  security add-generic-password \
    -a "${SV_KEYCHAIN_ACCOUNT}" \
    -s "${SV_SERVICE_PREFIX}${key}" \
    -w "${value}" \
    -U 2>/dev/null
}

# Retrieve a secret from the Keychain.
# Returns 1 if not found.
kc_get() {
  local key="$1"
  security find-generic-password \
    -a "${SV_KEYCHAIN_ACCOUNT}" \
    -s "${SV_SERVICE_PREFIX}${key}" \
    -w 2>/dev/null
}

# Delete a secret from the Keychain.
kc_rm() {
  local key="$1"
  security delete-generic-password \
    -a "${SV_KEYCHAIN_ACCOUNT}" \
    -s "${SV_SERVICE_PREFIX}${key}" >/dev/null 2>&1
}

# List all sv secret names from the Keychain.
# Parses `security dump-keychain` output for our service prefix.
kc_ls() {
  security dump-keychain 2>/dev/null \
    | grep "\"svce\"<blob>=\"${SV_SERVICE_PREFIX}" \
    | sed "s/.*\"${SV_SERVICE_PREFIX}\(.*\)\"/\1/" \
    | sort -u \
    || true
}

# ─── Manifest ─────────────────────────────────────────────────────────────────

# Walk up from the current directory to find a .secrets manifest.
# Returns the path if found, nothing otherwise.
find_manifest() {
  local dir="$PWD"
  while [[ "$dir" != "/" ]]; do
    if [[ -f "${dir}/${SV_MANIFEST}" ]]; then
      printf "%s" "${dir}/${SV_MANIFEST}"
      return
    fi
    dir="$(dirname "$dir")"
  done
}

# Read secret names from a .secrets manifest file.
# Skips blank lines and comments (#).
read_manifest() {
  local manifest_path="$1"
  if [[ ! -f "${manifest_path}" ]]; then
    return
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    # Trim whitespace
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    # Skip empty and comments
    [[ -z "$line" || "$line" == \#* ]] && continue
    printf "%s\n" "$line"
  done < "${manifest_path}"
}

# ─── Resolve which secrets to inject ──────────────────────────────────────────

# If a .secrets manifest is found (searching up from cwd), use it to scope.
# Otherwise, inject all sv secrets.
# Fails if a manifest lists a key not found in the keychain.
resolve_secret_names() {
  local manifest_path
  manifest_path="$(find_manifest)"

  if [[ -n "${manifest_path}" ]]; then
    local manifest_keys
    manifest_keys="$(read_manifest "${manifest_path}")"
    if [[ -z "${manifest_keys}" ]]; then
      return
    fi

    # Validate every manifest key exists in the keychain
    local missing=()
    while IFS= read -r key; do
      if ! kc_get "$key" >/dev/null 2>&1; then
        missing+=("$key")
      fi
    done <<< "$manifest_keys"

    if [[ ${#missing[@]} -gt 0 ]]; then
      die "missing required secrets (listed in ${manifest_path}): ${missing[*]}"
    fi

    printf "%s\n" "${manifest_keys}"
  else
    kc_ls
  fi
}

# ─── Commands ─────────────────────────────────────────────────────────────────

cmd_set() {
  local key="${1:-}"

  [[ -z "$key" ]] && die "usage: sv set <KEY>"

  # Reject positional value argument to avoid shell history leakage
  if [[ $# -gt 1 ]]; then
    die "do not pass the value as an argument (it leaks into shell history). Use: sv set ${key}"
  fi

  # Validate key looks like an env var name
  if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    die "invalid key '${key}' — must be a valid env var name (letters, digits, underscores)"
  fi

  local value
  if [[ ! -t 0 ]]; then
    # Reading from pipe/stdin
    IFS= read -r value
  else
    # Interactive prompt
    printf "value for %s: " "$key" >&2
    read -rs value
    printf "\n" >&2
  fi

  [[ -z "$value" ]] && die "no value provided"

  kc_set "$key" "$value"
  printf "sv: stored %s\n" "$key" >&2
}

cmd_get() {
  local key="${1:-}"
  [[ -z "$key" ]] && die "usage: sv get <KEY>"

  # Guard: stdout must be a real terminal.
  # When an agent captures output (pipes, $(), redirection) stdout is NOT a TTY.
  # This blocks agents from reading secret values through sv get.
  if [[ ! -t 1 ]]; then
    die "sv get requires an interactive terminal (stdout must be a TTY)"
  fi

  local value
  value="$(kc_get "$key")" || die "secret not found: $key"
  printf "%s\n" "$value"
}

cmd_rm() {
  local key="${1:-}"
  [[ -z "$key" ]] && die "usage: sv rm <KEY>"

  kc_rm "$key" || die "secret not found: $key"
  printf "sv: removed %s\n" "$key" >&2
}

cmd_ls() {
  local keys
  keys="$(kc_ls)"
  if [[ -z "$keys" ]]; then
    printf "sv: no secrets stored\n" >&2
    return
  fi
  printf "%s\n" "$keys"
}

cmd_exec() {
  # Collect env vars
  local names
  names="$(resolve_secret_names)"

  if [[ -z "$names" ]]; then
    # No secrets to inject, just run the command
    exec "$@"
  fi

  # Build env assignments
  local env_args=()
  while IFS= read -r key; do
    local value
    value="$(kc_get "$key" 2>/dev/null)" || continue
    env_args+=("${key}=${value}")
  done <<< "$names"

  # Use env to inject and exec the command
  exec env "${env_args[@]}" "$@"
}

cmd_help() {
  cat <<'HELP'
sv — simple secret vault for local dev

Usage:
  sv set <KEY>               Store a secret (prompts or reads stdin)
  sv get <KEY>               Print a secret value (TTY only — blocked when piped)
  sv rm <KEY>                Delete a secret
  sv ls                      List secret names (never values)
  sv exec -- <cmd> [args]    Run a command with secrets as env vars
  sv help                    Show this help

Project manifests:
  Create a .secrets file (safe to commit) listing secret names your project needs:

    # .secrets
    OPENAI_API_KEY
    DATABASE_URL

  When present, sv exec only injects listed secrets and fails if any
  are missing from the keychain. When absent, all stored secrets are injected.

  The manifest is found by searching up from the current directory.

Examples:
  sv set OPENAI_API_KEY                   # prompts for value
  echo "sk-..." | sv set OPENAI_API_KEY   # pipe from stdin
  sv ls                                   # shows: OPENAI_API_KEY
  sv exec -- npm run dev                  # runs with secrets injected
  sv exec -- node test.js                 # same

Agent usage:
  Agents should prefix commands with sv exec -- to get secrets without
  ever seeing the actual values:

    sv exec -- npm test
    sv exec -- node scripts/call-api.js
HELP
}

# ─── Main ─────────────────────────────────────────────────────────────────────

need_cmd security

cmd="${1:-help}"
shift || true

case "$cmd" in
  set)        cmd_set "$@" ;;
  get)        cmd_get "$@" ;;
  rm|remove)  cmd_rm "$@" ;;
  ls|list)    cmd_ls ;;
  exec)
    # Skip the -- separator if present
    [[ "${1:-}" == "--" ]] && shift
    [[ $# -eq 0 ]] && die "usage: sv exec -- <command> [args...]"
    cmd_exec "$@"
    ;;
  help|--help|-h)
    cmd_help ;;
  *)
    die "unknown command: $cmd (try: sv help)" ;;
esac
