#!/usr/bin/env bash
#
# sv — simple secret vault for local dev
#
# Stores secrets in macOS Keychain on macOS and password-store on Linux.
# Never stores values in plaintext files. Never prints values unless explicitly asked.
#
# Usage:
#   sv set <KEY>               Store a secret (prompts or reads stdin)
#   sv get <KEY>               Print a secret value (interactive TTY only)
#   sv rm <KEY>                Delete a secret
#   sv ls                      List secret names (never values)
#   sv exec -- <cmd> [args]    Run a command with secrets as env vars
#   sv unlock <KEY>            Unlock Linux GPG agent without printing a secret
#   sv doctor                  Check backend setup and common failures
#   sv update                  Update sv to the latest version
#   sv version                 Print version
#   sv help                    Show this help
#

set -euo pipefail

readonly SV_VERSION="0.1.0"
readonly SV_REPO="figelwump/sv"
readonly SV_RAW_URL="https://raw.githubusercontent.com/${SV_REPO}/main/sv"
readonly SV_SERVICE_PREFIX="${SV_SERVICE_PREFIX:-sv:}"
readonly SV_KEYCHAIN_ACCOUNT="${USER}"
readonly SV_MANIFEST=".secrets"
readonly SV_PASS_NAMESPACE="sv"
readonly SV_BACKEND_FAILURE_STATUS=2

# ─── Helpers ───────────────────────────────────────────────────────────────────

die() {
  printf "sv: %s\n" "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

linux_install_hint() {
  if command -v apt-get >/dev/null 2>&1; then
    printf "Install with: sudo apt install -y pass gnupg pinentry-curses"
  else
    printf "Install pass, gnupg, and a pinentry program for your Linux distro."
  fi
}

detect_backend() {
  case "$(uname -s)" in
    Darwin) printf "keychain\n" ;;
    Linux) printf "pass\n" ;;
    *) die "unsupported OS: $(uname -s)" ;;
  esac
}

readonly SV_BACKEND="$(detect_backend)"

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

# ─── Linux password-store operations ──────────────────────────────────────────

pass_store_dir() {
  printf "%s\n" "${PASSWORD_STORE_DIR:-${HOME}/.password-store}"
}

pass_entry_path() {
  local key="$1"
  printf "%s/%s\n" "${SV_PASS_NAMESPACE}" "${key}"
}

pass_entry_file() {
  local key="$1"
  printf "%s/%s.gpg\n" "$(pass_store_dir)" "$(pass_entry_path "$key")"
}

pass_store_initialized() {
  [[ -f "$(pass_store_dir)/.gpg-id" ]]
}

pass_prepare_tty() {
  local tty_name

  [[ -t 0 ]] || return 0

  tty_name="$(tty 2>/dev/null || true)"
  [[ -n "${tty_name}" && "${tty_name}" != "not a tty" ]] || return 0

  export GPG_TTY="${tty_name}"

  if command -v gpg-connect-agent >/dev/null 2>&1; then
    gpg-connect-agent updatestartuptty /bye >/dev/null 2>&1 || true
  fi
}

pass_require_ready() {
  need_cmd pass
  need_cmd gpg

  if ! pass_store_initialized; then
    die "Linux password store is not initialized. Run 'pass init <gpg-id>' before using sv."
  fi

  pass_prepare_tty
}

pass_failure_preposition() {
  case "$1" in
    read) printf "from" ;;
    *)    printf "in" ;;
  esac
}

pass_failure_is_prompt_error() {
  local err="$1"

  case "$err" in
    *"No pinentry"*|*"Inappropriate ioctl for device"*|*"Operation cancelled"*|*"Screen or window too small"*)
      return 0
      ;;
  esac

  return 1
}

pass_failure_is_missing_key_error() {
  local err="$1"

  case "$err" in
    *"No secret key"*|*"secret key not available"*)
      return 0
      ;;
  esac

  return 1
}

pass_emit_failure() {
  local action="$1" key="$2" err="$3"
  local subject="a secret"
  local preposition clean_err quoted_pwd quoted_key

  [[ -n "${key}" ]] && subject="${key}"
  preposition="$(pass_failure_preposition "${action}")"

  if pass_failure_is_prompt_error "${err}"; then
    printf "sv: failed to %s %s %s the Linux password store because gpg-agent is locked or cannot prompt in this session.\n" "${action}" "${subject}" "${preposition}" >&2
    if [[ -n "${key}" ]]; then
      printf -v quoted_key "%q" "${key}"
      if [[ -t 0 && -t 2 ]]; then
        printf "sv: human action: make sure this SSH terminal can show pinentry, then run:\n" >&2
        printf "sv:   sv unlock %s\n" "${quoted_key}" >&2
      else
        printf -v quoted_pwd "%q" "${PWD}"
        printf "sv: agent action: ask the human user to open an interactive SSH terminal and run:\n" >&2
        printf "sv:   cd %s && sv unlock %s\n" "${quoted_pwd}" "${quoted_key}" >&2
        printf "sv: then retry this command.\n" >&2
      fi
    else
      printf "sv: agent action: ask the human user to run 'sv unlock <KEY>' in an interactive SSH terminal, then retry this command.\n" >&2
    fi
    return
  fi

  if pass_failure_is_missing_key_error "${err}"; then
    printf "sv: failed to %s %s %s the Linux password store because the private GPG key is not available.\n" "${action}" "${subject}" "${preposition}" >&2
    printf "sv: run 'sv doctor' on the Linux host to check the password-store and GPG setup.\n" >&2
    return
  fi

  if [[ -n "${err}" ]]; then
    clean_err="${err//$'\n'/ }"
    printf "sv: failed to %s %s %s the Linux password store: %s\n" "${action}" "${subject}" "${preposition}" "${clean_err}" >&2
    return
  fi

  printf "sv: failed to %s %s %s the Linux password store.\n" "${action}" "${subject}" "${preposition}" >&2
}

pass_handle_failure() {
  pass_emit_failure "$@"
  exit 1
}

pass_has() {
  [[ -f "$(pass_entry_file "$1")" ]]
}

pass_set() {
  local key="$1" value="$2"

  local err_file
  err_file="$(mktemp)"

  if printf "%s\n" "$value" | pass insert --multiline --force "$(pass_entry_path "$key")" >/dev/null 2>"${err_file}"; then
    rm -f "${err_file}"
    return 0
  fi

  local err
  err="$(<"${err_file}")"
  rm -f "${err_file}"
  pass_handle_failure "store" "${key}" "${err}"
}

pass_get() {
  local key="$1"

  if ! pass_has "$key"; then
    return 1
  fi

  local err_file
  err_file="$(mktemp)"
  if pass show "$(pass_entry_path "$key")" 2>"${err_file}"; then
    rm -f "${err_file}"
    return 0
  fi

  local err
  err="$(<"${err_file}")"
  rm -f "${err_file}"
  pass_emit_failure "read" "${key}" "${err}"
  return "${SV_BACKEND_FAILURE_STATUS}"
}

pass_rm() {
  local key="$1"

  pass rm --force "$(pass_entry_path "$key")" >/dev/null 2>&1
}

pass_ls() {
  local root
  root="$(pass_store_dir)/${SV_PASS_NAMESPACE}"

  [[ -d "${root}" ]] || return 0

  find "${root}" -type f -name '*.gpg' -print \
    | sed "s#^${root}/##" \
    | sed 's/\.gpg$//' \
    | sort -u
}

# ─── Backend dispatch ─────────────────────────────────────────────────────────

store_require_ready() {
  case "${SV_BACKEND}" in
    keychain)
      need_cmd security
      ;;
    pass)
      pass_require_ready
      ;;
  esac
}

store_has() {
  case "${SV_BACKEND}" in
    keychain) kc_get "$1" >/dev/null 2>&1 ;;
    pass)     pass_has "$1" ;;
  esac
}

store_set() {
  store_require_ready

  case "${SV_BACKEND}" in
    keychain) kc_set "$@" ;;
    pass)     pass_set "$@" ;;
  esac
}

store_get() {
  store_require_ready

  case "${SV_BACKEND}" in
    keychain) kc_get "$1" ;;
    pass)     pass_get "$1" ;;
  esac
}

store_rm() {
  store_require_ready

  case "${SV_BACKEND}" in
    keychain) kc_rm "$1" ;;
    pass)     pass_rm "$1" ;;
  esac
}

store_ls() {
  case "${SV_BACKEND}" in
    keychain)
      need_cmd security
      kc_ls
      ;;
    pass)
      pass_ls
      ;;
  esac
}

# ─── Doctor ───────────────────────────────────────────────────────────────────

DOCTOR_FAILURES=0
DOCTOR_WARNINGS=0
DOCTOR_NEXT_STEPS=()

doctor_info() {
  printf "[info] %s\n" "$1"
}

doctor_ok() {
  printf "[ok] %s\n" "$1"
}

doctor_warn() {
  DOCTOR_WARNINGS=$((DOCTOR_WARNINGS + 1))
  printf "[warn] %s\n" "$1"
}

doctor_fail() {
  DOCTOR_FAILURES=$((DOCTOR_FAILURES + 1))
  printf "[fail] %s\n" "$1"
}

doctor_next() {
  local step="$1"
  local existing

  for existing in "${DOCTOR_NEXT_STEPS[@]:-}"; do
    [[ "${existing}" == "${step}" ]] && return
  done

  DOCTOR_NEXT_STEPS+=("${step}")
}

doctor_print_next_steps() {
  local step

  [[ ${#DOCTOR_NEXT_STEPS[@]} -gt 0 ]] || return 0

  printf "Next steps:\n"
  for step in "${DOCTOR_NEXT_STEPS[@]}"; do
    printf "  %s\n" "${step}"
  done

  return 0
}

doctor_check_cmd() {
  local cmd="$1" label="$2" hint="${3:-}"
  local path
  path="$(command -v "$cmd" 2>/dev/null || true)"

  if [[ -n "${path}" ]]; then
    doctor_ok "${label}: ${path}"
    return 0
  fi

  if [[ -n "${hint}" ]]; then
    doctor_fail "${label}: missing. ${hint}"
  else
    doctor_fail "${label}: missing."
  fi
  return 1
}

doctor_check_keychain() {
  local err_file err

  doctor_info "backend: keychain"

  if doctor_check_cmd security "security command"; then
    if security dump-keychain >/dev/null 2>&1; then
      doctor_ok "macOS Keychain listing is accessible"
    else
      doctor_fail "macOS Keychain listing is not accessible in this session"
    fi

    err_file="$(mktemp)"
    if security find-generic-password \
      -a "${SV_KEYCHAIN_ACCOUNT}" \
      -s "${SV_SERVICE_PREFIX}__sv_doctor_probe__" \
      -w >/dev/null 2>"${err_file}"; then
      doctor_ok "macOS Keychain lookup is accessible"
    else
      err="$(<"${err_file}")"
      if [[ "${err}" == *"could not be found"* ]]; then
        doctor_ok "macOS Keychain lookup is accessible"
      else
        err="${err//$'\n'/ }"
        doctor_fail "macOS Keychain lookup failed: ${err}"
      fi
    fi
    rm -f "${err_file}"
  fi
}

doctor_check_pass() {
  local pass_ok=0 gpg_ok=0
  local store_dir gpg_home agent_socket pinentry_cmd=""
  local gpg_ids=()
  local gpg_id=""

  store_dir="$(pass_store_dir)"
  gpg_home="${GNUPGHOME:-${HOME}/.gnupg}"

  doctor_info "backend: pass"
  doctor_info "password store dir: ${store_dir}"
  doctor_info "gpg home: ${gpg_home}"

  if doctor_check_cmd pass "pass command" "$(linux_install_hint)"; then
    pass_ok=1
  fi

  if doctor_check_cmd gpg "gpg command" "$(linux_install_hint)"; then
    gpg_ok=1
  fi

  if [[ ${gpg_ok} -eq 1 ]]; then
    while IFS= read -r gpg_id; do
      [[ -n "${gpg_id}" ]] && gpg_ids+=("${gpg_id}")
    done < <(gpg --batch --with-colons --list-secret-keys 2>/dev/null | awk -F: '$1 == "sec" { print $5 }')
  fi

  if [[ ${pass_ok} -eq 1 ]]; then
    if pass_store_initialized; then
      doctor_ok "password store initialized: ${store_dir}/.gpg-id"
    else
      doctor_fail "password store not initialized. Run: pass init <gpg-id>"
      if [[ ${#gpg_ids[@]} -gt 0 ]]; then
        doctor_next "Initialize pass with: pass init ${gpg_ids[0]}"
      fi
    fi
  fi

  if [[ ${gpg_ok} -eq 1 ]]; then
    if [[ ${#gpg_ids[@]} -gt 0 ]]; then
      doctor_ok "at least one secret GPG key is available"
    else
      doctor_fail "no secret GPG key found. Generate or import a key, then run: pass init <gpg-id>"
      doctor_next "Create a key with: gpg --full-generate-key"
      doctor_next "List keys with: gpg --list-secret-keys --keyid-format=long"
      doctor_next "Initialize pass with: pass init <gpg-id>"
    fi
  fi

  if command -v gpgconf >/dev/null 2>&1; then
    agent_socket="$(gpgconf --list-dirs agent-socket 2>/dev/null || true)"
    if [[ -n "${agent_socket}" && -S "${agent_socket}" ]]; then
      doctor_ok "gpg-agent socket present: ${agent_socket}"
    else
      doctor_warn "gpg-agent socket not detected. Headless sessions may need an unlocked gpg-agent."
    fi
  else
    doctor_warn "gpgconf not found; cannot inspect gpg-agent state"
  fi

  for candidate in pinentry pinentry-curses pinentry-tty pinentry-gtk-2 pinentry-gnome3; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      pinentry_cmd="$(command -v "${candidate}")"
      break
    fi
  done

  if [[ -n "${pinentry_cmd}" ]]; then
    doctor_ok "pinentry available: ${pinentry_cmd}"
  else
    doctor_warn "no pinentry program found in PATH. $(linux_install_hint)"
  fi

  if [[ ! -t 0 || ! -t 2 ]]; then
    doctor_warn "session is non-interactive. If gpg-agent is locked, sv exec cannot satisfy a GPG prompt here."
    doctor_next "Agent action: ask the human user to run 'sv unlock <KEY>' in an interactive SSH terminal before retrying non-interactive sv exec."
  elif [[ -z "${GPG_TTY:-}" ]]; then
    doctor_warn "GPG_TTY is not set. Some terminal sessions need: export GPG_TTY=\$(tty)"
    doctor_next "Set it in this shell with: export GPG_TTY=\$(tty)"
  fi
}

cmd_doctor() {
  DOCTOR_FAILURES=0
  DOCTOR_WARNINGS=0
  DOCTOR_NEXT_STEPS=()

  doctor_info "sv version: ${SV_VERSION}"

  case "${SV_BACKEND}" in
    keychain) doctor_check_keychain ;;
    pass)     doctor_check_pass ;;
  esac

  if [[ ${DOCTOR_FAILURES} -gt 0 ]]; then
    printf "sv doctor: %d failure(s), %d warning(s)\n" "${DOCTOR_FAILURES}" "${DOCTOR_WARNINGS}"
    doctor_print_next_steps
    return 1
  fi

  if [[ ${DOCTOR_WARNINGS} -gt 0 ]]; then
    printf "sv doctor: ok with %d warning(s)\n" "${DOCTOR_WARNINGS}"
  else
    printf "sv doctor: ok\n"
  fi

  doctor_print_next_steps
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
# Fails if a manifest lists a key not found in the active backend.
resolve_secret_names() {
  local manifest_path
  manifest_path="$(find_manifest)"

  if [[ -n "${manifest_path}" ]]; then
    local manifest_keys
    manifest_keys="$(read_manifest "${manifest_path}")"
    if [[ -z "${manifest_keys}" ]]; then
      return
    fi

    store_require_ready

    # Validate every manifest key exists in the active backend
    local missing=()
    while IFS= read -r key; do
      if ! store_has "$key"; then
        missing+=("$key")
      fi
    done <<< "$manifest_keys"

    if [[ ${#missing[@]} -gt 0 ]]; then
      die "missing required secrets (listed in ${manifest_path}): ${missing[*]}"
    fi

    printf "%s\n" "${manifest_keys}"
  else
    store_ls
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

  store_set "$key" "$value"
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
  if value="$(store_get "$key")"; then
    printf "%s\n" "$value"
    return 0
  else
    local status=$?
    [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]] && return 1

    die "secret not found: $key"
  fi
}

cmd_unlock() {
  local key="${1:-}"
  local quoted_key

  [[ -z "$key" || $# -gt 1 ]] && die "usage: sv unlock <KEY>"

  if [[ "${SV_BACKEND}" != "pass" ]]; then
    die "sv unlock is only needed on Linux password-store"
  fi

  if [[ ! -t 0 || ! -t 2 ]]; then
    printf -v quoted_key "%q" "${key}"
    die "sv unlock requires an interactive terminal. Agent action: ask the human user to run 'sv unlock ${quoted_key}' in an interactive SSH terminal, then retry the original command."
  fi

  store_require_ready

  if ! store_has "$key"; then
    die "secret not found: $key"
  fi

  if store_get "$key" >/dev/null; then
    printf "sv: unlocked Linux password store for %s\n" "$key" >&2
    return 0
  else
    local status=$?
    [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]] && return 1

    die "secret not found: $key"
  fi
}

cmd_rm() {
  local key="${1:-}"
  [[ -z "$key" ]] && die "usage: sv rm <KEY>"

  store_rm "$key" || die "secret not found: $key"
  printf "sv: removed %s\n" "$key" >&2
}

cmd_ls() {
  local keys
  keys="$(store_ls)"
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
    if value="$(store_get "$key")"; then
      env_args+=("${key}=${value}")
      continue
    else
      local status=$?
      [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]] && return 1

      die "failed to resolve secret: $key"
    fi
  done <<< "$names"

  # Use env to inject and exec the command
  exec env "${env_args[@]}" "$@"
}

cmd_update() {
  need_cmd curl

  # Find where sv is currently installed
  local self
  self="$(realpath "$0")"

  printf "sv: updating from %s ...\n" "${SV_RAW_URL}" >&2

  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT

  if ! curl -fsSL "${SV_RAW_URL}" -o "$tmp"; then
    die "failed to download update"
  fi

  # Basic sanity check: must start with a shebang
  if ! head -1 "$tmp" | grep -q '^#!/'; then
    die "downloaded file doesn't look like a script — aborting"
  fi

  chmod +x "$tmp"
  mv "$tmp" "$self"
  trap - EXIT

  # Show new version
  local new_version
  new_version="$("$self" version 2>/dev/null || echo "unknown")"
  printf "sv: updated to %s (%s)\n" "$new_version" "$self" >&2
}

cmd_version() {
  printf "%s\n" "${SV_VERSION}"
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
  sv unlock <KEY>            Unlock Linux GPG agent without printing a secret
  sv doctor                  Check backend setup and common failures
  sv update                  Update sv to the latest version
  sv version                 Print version
  sv help                    Show this help

Project manifests:
  Create a .secrets file (safe to commit) listing secret names your project needs:

    # .secrets
    OPENAI_API_KEY
    DATABASE_URL

  When present, sv exec only injects listed secrets and fails if any
  are missing from the active backend. When absent, all stored secrets are injected.

  The manifest is found by searching up from the current directory.

Examples:
  sv set OPENAI_API_KEY                   # prompts for value
  echo "sk-..." | sv set OPENAI_API_KEY   # pipe from stdin
  sv ls                                   # shows: OPENAI_API_KEY
  sv exec -- npm run dev                  # runs with secrets injected
  sv exec -- node test.js                 # same
  sv unlock OPENAI_API_KEY                # Linux: warm gpg-agent interactively

Agent usage:
  Agents should prefix commands with sv exec -- to get secrets without
  ever seeing the actual values:

    sv exec -- npm test
    sv exec -- node scripts/call-api.js

Backends:
  macOS uses the Keychain via `security`.
  Linux uses password-store via `pass`.
HELP
}

# ─── Main ─────────────────────────────────────────────────────────────────────

cmd="${1:-help}"
shift || true

case "$cmd" in
  set)        cmd_set "$@" ;;
  get)        cmd_get "$@" ;;
  unlock)     cmd_unlock "$@" ;;
  rm|remove)  cmd_rm "$@" ;;
  ls|list)    cmd_ls ;;
  doctor)     cmd_doctor ;;
  exec)
    # Skip the -- separator if present
    [[ "${1:-}" == "--" ]] && shift
    [[ $# -eq 0 ]] && die "usage: sv exec -- <command> [args...]"
    cmd_exec "$@"
    ;;
  update)    cmd_update ;;
  version|--version|-v)
    cmd_version ;;
  help|--help|-h)
    cmd_help ;;
  *)
    die "unknown command: $cmd (try: sv help)" ;;
esac
