#!/usr/bin/env bash
#
# sv — simple secret vault for local dev
#
# Stores secrets in macOS Keychain. Injects them into processes on demand.
# Never stores values in files. Never prints values unless explicitly asked.
#
# Usage:
#   sv set <KEY> [value]       Store a secret (prompts if no value given)
#   sv get <KEY>               Print a secret value
#   sv rm <KEY>                Delete a secret
#   sv ls                      List secret names (never values)
#   sv exec -- <cmd> [args]    Run a command with secrets as env vars
#   sv env                     Print export statements for eval
#   sv shell-hook              Print shell integration code for .zshrc
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

# If a .secrets manifest exists in the current dir, use it to scope.
# Otherwise, inject all sv secrets.
resolve_secret_names() {
  local manifest_keys
  manifest_keys="$(read_manifest "${SV_MANIFEST}")"

  if [[ -n "${manifest_keys}" ]]; then
    printf "%s\n" "${manifest_keys}"
  else
    kc_ls
  fi
}

# ─── Commands ─────────────────────────────────────────────────────────────────

cmd_set() {
  local key="${1:-}"
  local value="${2:-}"

  [[ -z "$key" ]] && die "usage: sv set <KEY> [value]"

  # Validate key looks like an env var name
  if [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    die "invalid key '${key}' — must be a valid env var name (letters, digits, underscores)"
  fi

  if [[ -z "$value" ]]; then
    printf "value for %s: " "$key" >&2
    # Read without echo for security
    read -rs value
    printf "\n" >&2
    [[ -z "$value" ]] && die "no value provided"
  fi

  kc_set "$key" "$value"
  printf "sv: stored %s\n" "$key" >&2
}

cmd_get() {
  local key="${1:-}"
  [[ -z "$key" ]] && die "usage: sv get <KEY>"

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

cmd_env() {
  local names
  names="$(resolve_secret_names)"
  [[ -z "$names" ]] && return

  while IFS= read -r key; do
    local value
    value="$(kc_get "$key" 2>/dev/null)" || continue
    # Escape single quotes in value for safe eval
    value="${value//\'/\'\\\'\'}"
    printf "export %s='%s'\n" "$key" "$value"
  done <<< "$names"
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

cmd_shell_hook() {
  cat <<'HOOK'
# sv shell integration — add to .zshrc:
#   eval "$(sv shell-hook)"
sv() {
  local sv_bin
  sv_bin="$(command -v sv 2>/dev/null)" || { echo "sv: not found in PATH" >&2; return 1; }
  if [[ "${1:-}" == "exec" ]]; then
    # For exec, run directly so env vars are injected into the subprocess
    command "$sv_bin" "$@"
  elif [[ "${1:-}" == "env" ]]; then
    # For env, eval the exports in the current shell
    eval "$(command "$sv_bin" env)"
  else
    command "$sv_bin" "$@"
  fi
}

# Auto-load secrets on shell startup
if command -v sv >/dev/null 2>&1; then
  eval "$(command sv env 2>/dev/null)"
fi
HOOK
}

cmd_help() {
  cat <<'HELP'
sv — simple secret vault for local dev

Usage:
  sv set <KEY> [value]       Store a secret (prompts interactively if no value)
  sv get <KEY>               Print a secret value
  sv rm <KEY>                Delete a secret
  sv ls                      List secret names (never values)
  sv exec -- <cmd> [args]    Run a command with secrets as env vars
  sv env                     Print export statements (for eval)
  sv shell-hook              Print shell integration code
  sv help                    Show this help

Project manifests:
  Create a .secrets file (safe to commit) listing secret names your project needs:

    # .secrets
    OPENAI_API_KEY
    DATABASE_URL

  When present, sv exec and sv env only inject listed secrets.
  When absent, all stored secrets are injected.

Examples:
  sv set OPENAI_API_KEY sk-proj-...
  sv set DATABASE_URL                     # prompts for value
  sv ls                                   # shows: OPENAI_API_KEY, DATABASE_URL
  sv exec -- npm run dev                  # runs with secrets injected
  sv exec -- node test.js                 # same
  eval "$(sv env)"                        # export into current shell

Agent usage:
  Agents should prefix commands with sv exec -- to get secrets without
  ever seeing the actual values:

    sv exec -- npm test
    sv exec -- node scripts/call-api.js

Shell integration:
  eval "$(sv shell-hook)"                 # add to .zshrc once
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
  env)        cmd_env ;;
  exec)
    # Skip the -- separator if present
    [[ "${1:-}" == "--" ]] && shift
    [[ $# -eq 0 ]] && die "usage: sv exec -- <command> [args...]"
    cmd_exec "$@"
    ;;
  shell-hook) cmd_shell_hook ;;
  help|--help|-h)
    cmd_help ;;
  *)
    die "unknown command: $cmd (try: sv help)" ;;
esac
