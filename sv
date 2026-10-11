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
#   sv exec [--strict] -- <cmd> [args]
#   sv exec --key <KEY> [--key <KEY>...] -- <cmd> [args]
#   sv exec --all-secrets -- <cmd> [args]
#                               Run a command with selected secrets as env vars
#   sv sync [KEY...]           Copy secrets from 1Password into the local store
#   sv unlock <KEY>            Unlock Linux GPG agent without printing a secret
#   sv doctor                  Check backend setup and common failures
#   sv update                  Update sv to the latest version
#   sv version                 Print version
#   sv help                    Show this help
#

set -euo pipefail

readonly SV_VERSION="0.3.0"
readonly SV_REPO="figelwump/sv"
readonly SV_RAW_URL="https://raw.githubusercontent.com/${SV_REPO}/main/sv"
readonly SV_SERVICE_PREFIX="${SV_SERVICE_PREFIX:-sv:}"
readonly SV_KEYCHAIN_ACCOUNT="${USER}"
readonly SV_MANIFEST=".secrets"
readonly SV_PASS_NAMESPACE="sv"
readonly SV_BACKEND_FAILURE_STATUS=2
readonly SV_PASS_TIMEOUT_SECONDS="${SV_PASS_TIMEOUT_SECONDS:-8}"
readonly SV_OP_VAULT="${SV_OP_VAULT:-sv}"
readonly SV_OP_FIELD="${SV_OP_FIELD:-password}"
readonly SV_OP_TOKEN_KEY="OP_SERVICE_ACCOUNT_TOKEN"
readonly SV_OP_TIMEOUT_SECONDS="${SV_OP_TIMEOUT_SECONDS:-60}"
readonly SV_OP_TIMEOUT_STATUS=124

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

# Return success only for a genuine Keychain item-not-found error.
kc_failure_is_not_found() {
  local status="$1" err="$2"
  # macOS reports errSecItemNotFound as exit 44. Keep the C-locale message
  # fallback for older security variants that do not preserve that status.
  [[ "${status}" -eq 44 || "${err}" == *"could not be found"* ]]
}

kc_emit_access_failure() {
  local action="$1" key="${2:-}" err="${3:-}"
  local subject="the sv Keychain" clean_err

  [[ -n "${key}" ]] && subject="${key} in the sv Keychain"
  clean_err="${err//$'\n'/ }"

  if [[ -n "${clean_err}" ]]; then
    printf "sv: failed to %s %s: %s\n" "${action}" "${subject}" "${clean_err}" >&2
  else
    printf "sv: failed to %s %s.\n" "${action}" "${subject}" >&2
  fi
  printf "sv: macOS Keychain may be inaccessible in this session; if running in a sandbox, retry with authorized Keychain access.\n" >&2
}

# Retrieve a secret from the Keychain.
# Returns 1 if not found and 2 if the backend is inaccessible.
kc_get() {
  local key="$1"
  local err_file err status
  err_file="$(mktemp)"

  if LC_ALL=C security find-generic-password \
    -a "${SV_KEYCHAIN_ACCOUNT}" \
    -s "${SV_SERVICE_PREFIX}${key}" \
    -w 2>"${err_file}"; then
    rm -f "${err_file}"
    return 0
  else
    status=$?
  fi

  err="$(<"${err_file}")"
  rm -f "${err_file}"
  if kc_failure_is_not_found "${status}" "${err}"; then
    return 1
  fi

  kc_emit_access_failure "read" "${key}" "${err}"
  return "${SV_BACKEND_FAILURE_STATUS}"
}

kc_has() {
  local key="$1"
  local err_file err status
  err_file="$(mktemp)"

  if LC_ALL=C security find-generic-password \
    -a "${SV_KEYCHAIN_ACCOUNT}" \
    -s "${SV_SERVICE_PREFIX}${key}" >/dev/null 2>"${err_file}"; then
    rm -f "${err_file}"
    return 0
  else
    status=$?
  fi

  err="$(<"${err_file}")"
  rm -f "${err_file}"
  if kc_failure_is_not_found "${status}" "${err}"; then
    return 1
  fi

  kc_emit_access_failure "look up" "${key}" "${err}"
  return "${SV_BACKEND_FAILURE_STATUS}"
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
  local dump_file err_file output_file err output line service
  dump_file="$(mktemp)"
  err_file="$(mktemp)"
  output_file="$(mktemp)"

  if ! LC_ALL=C security dump-keychain >"${dump_file}" 2>"${err_file}"; then
    err="$(<"${err_file}")"
    rm -f "${dump_file}" "${err_file}" "${output_file}"
    kc_emit_access_failure "list" "" "${err}"
    return "${SV_BACKEND_FAILURE_STATUS}"
  fi

  # Keep the case statements outside command substitution: macOS Bash 3.2
  # misparses their closing parentheses as the end of the substitution.
  if {
    while IFS= read -r line; do
      case "${line}" in
        *'"svce"<blob>="'*)
          service="${line#*'"svce"<blob>="'}"
          service="${service%%\"*}"
          case "${service}" in
            "${SV_SERVICE_PREFIX}"*)
              printf "%s\n" "${service#"${SV_SERVICE_PREFIX}"}"
              ;;
          esac
          ;;
      esac
    done < "${dump_file}"
    : # An empty listing is successful; keep pipefail focused on real parser/sort errors.
  } | sort -u > "${output_file}"; then
    output="$(<"${output_file}")"
  else
    rm -f "${dump_file}" "${err_file}" "${output_file}"
    kc_emit_access_failure "parse the listing from" "" ""
    return "${SV_BACKEND_FAILURE_STATUS}"
  fi
  rm -f "${dump_file}" "${err_file}" "${output_file}"
  if [[ -n "${output}" ]]; then
    printf "%s\n" "${output}"
  fi
  return 0
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

pass_show_with_timeout() {
  local key="$1"

  if [[ -t 0 && -t 2 ]]; then
    pass show "$(pass_entry_path "$key")"
    return
  fi

  if command -v timeout >/dev/null 2>&1; then
    timeout "${SV_PASS_TIMEOUT_SECONDS}" pass show "$(pass_entry_path "$key")"
    return
  fi

  pass show "$(pass_entry_path "$key")"
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
    *"No pinentry"*|*"Inappropriate ioctl for device"*|*"Operation cancelled"*|*"Screen or window too small"*|*"timed out"*)
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

pass_emit_unlock_action() {
  local key="$1"
  local quoted_pwd quoted_key

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
}

pass_emit_failure() {
  local action="$1" key="$2" err="$3"
  local subject="a secret"
  local preposition clean_err

  [[ -n "${key}" ]] && subject="${key}"
  preposition="$(pass_failure_preposition "${action}")"

  if pass_failure_is_prompt_error "${err}"; then
    printf "sv: failed to %s %s %s the Linux password store because gpg-agent is locked or cannot prompt/use the private key in this session.\n" "${action}" "${subject}" "${preposition}" >&2
    if [[ "${err}" == *"timed out while reading the secret"* ]]; then
      printf "sv: gpg-agent or pinentry timed out while reading the secret.\n" >&2
    fi
    pass_emit_unlock_action "${key}"
    return
  fi

  if pass_failure_is_missing_key_error "${err}"; then
    printf "sv: failed to %s %s %s the Linux password store because GPG says the private key is unavailable.\n" "${action}" "${subject}" "${preposition}" >&2
    printf "sv: on Linux this can also happen when gpg-agent or pinentry cannot use the key in this session.\n" >&2
    pass_emit_unlock_action "${key}"
    printf "sv: if unlock fails too, run 'sv doctor' on the Linux host to check the password-store and GPG setup.\n" >&2
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
  local status
  if pass_show_with_timeout "$key" 2>"${err_file}"; then
    rm -f "${err_file}"
    return 0
  else
    status=$?
  fi

  local err
  err="$(<"${err_file}")"
  rm -f "${err_file}"
  if [[ "${status}" -eq 124 ]]; then
    err="${err}"$'\n'"gpg-agent or pinentry timed out while reading the secret"
  fi
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
    keychain) kc_has "$1" ;;
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

# ─── 1Password (optional) ─────────────────────────────────────────────────────
#
# 1Password is an optional upstream source. Only `sv sync` and the fetch of a
# missing required key in `sv exec` call the `op` CLI; every other command works
# without it. Each 1Password item in the vault is named after its sv key and
# holds the value in one field.

# Service-account token read from the local store. It is passed only to `op`
# through that child's environment and is never exported to other processes.
SV_OP_STORED_TOKEN=""

op_available() {
  command -v op >/dev/null 2>&1
}

op_fetch_enabled() {
  [[ "${SV_OP_FETCH:-1}" != "0" ]] && op_available
}

op_reference() {
  printf "op://%s/%s/%s\n" "${SV_OP_VAULT}" "$1" "${SV_OP_FIELD}"
}

# Load a stored service-account token when the caller did not provide one.
# This lets a headless machine authenticate `op` without a shell-profile export.
# Returns SV_BACKEND_FAILURE_STATUS when the local store cannot be read.
op_prepare_auth() {
  local token status

  [[ -z "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]] || return 0

  if store_has "${SV_OP_TOKEN_KEY}"; then
    if token="$(store_get "${SV_OP_TOKEN_KEY}")"; then
      SV_OP_STORED_TOKEN="${token}"
      return 0
    else
      status=$?
      [[ "${status}" -ne "${SV_BACKEND_FAILURE_STATUS}" ]] || return "${status}"
    fi
  else
    status=$?
    [[ "${status}" -ne "${SV_BACKEND_FAILURE_STATUS}" ]] || return "${status}"
  fi
}

# Run `op` with a time limit. `op` can wait indefinitely, for example on an
# authorization prompt nobody answers, and an agent's `sv exec` must fail
# instead of hanging. macOS has no timeout(1), so a background watchdog polls
# once per second. Its output goes to /dev/null so that a caller's command
# substitution does not wait for it. Returns SV_OP_TIMEOUT_STATUS on timeout.
op_cli() {
  local pid watchdog marker status

  [[ "${SV_OP_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]] \
    || die "SV_OP_TIMEOUT_SECONDS must be a whole number of seconds, not '${SV_OP_TIMEOUT_SECONDS}'"

  # The watchdog writes to this private file on timeout. Keeping the file
  # (rather than recreating its name) avoids a symlink race in a shared /tmp.
  marker="$(mktemp)"

  # Background `op` as a simple command so that $! is the op process itself
  # and the watchdog's kill reaches it.
  if [[ -n "${SV_OP_STORED_TOKEN}" ]]; then
    OP_SERVICE_ACCOUNT_TOKEN="${SV_OP_STORED_TOKEN}" op "$@" &
  else
    op "$@" &
  fi
  pid=$!
  (
    elapsed=0
    while kill -0 "${pid}" 2>/dev/null; do
      if [[ ${elapsed} -ge ${SV_OP_TIMEOUT_SECONDS} ]]; then
        printf "timeout\n" > "${marker}"
        kill "${pid}" 2>/dev/null
        sleep 2
        # Escalate if op ignores TERM.
        if kill -0 "${pid}" 2>/dev/null; then
          kill -KILL "${pid}" 2>/dev/null
        fi
        exit 0
      fi
      sleep 1
      elapsed=$((elapsed + 1))
    done
  ) </dev/null >/dev/null 2>&1 &
  watchdog=$!

  if wait "${pid}"; then
    status=0
  else
    status=$?
  fi
  kill "${watchdog}" 2>/dev/null || true
  wait "${watchdog}" 2>/dev/null || true

  if [[ -s "${marker}" ]]; then
    status="${SV_OP_TIMEOUT_STATUS}"
  fi
  rm -f "${marker}"
  return "${status}"
}

op_failure_detail() {
  local status="$1" err="$2"

  if [[ "${status}" -eq "${SV_OP_TIMEOUT_STATUS}" ]]; then
    printf "op did not respond within %s seconds (a 1Password prompt may be waiting; SV_OP_TIMEOUT_SECONDS sets the limit)\n" \
      "${SV_OP_TIMEOUT_SECONDS}"
  elif [[ -n "${err}" ]]; then
    printf "%s\n" "${err//$'\n'/ }"
  else
    printf "op exited with status %s\n" "${status}"
  fi
}

# Copy one key from 1Password into the active backend.
# Writes only status messages to stderr. On any failure the stored value is
# left unchanged. Returns SV_OP_TIMEOUT_STATUS when `op` timed out, so callers
# can stop instead of waiting again for each remaining key.
op_sync_key() {
  local key="$1"
  local reference err_file err value status
  reference="$(op_reference "${key}")"
  err_file="$(mktemp)"

  if value="$(op_cli read "${reference}" 2>"${err_file}")"; then
    rm -f "${err_file}"
  else
    status=$?
    err="$(<"${err_file}")"
    rm -f "${err_file}"
    printf "sv: could not read %s from 1Password (%s): %s\n" \
      "${key}" "${reference}" "$(op_failure_detail "${status}" "${err}")" >&2
    [[ "${status}" -ne "${SV_OP_TIMEOUT_STATUS}" ]] || return "${status}"
    return 1
  fi

  if [[ -z "${value}" ]]; then
    printf "sv: 1Password returned an empty value for %s (%s); the stored value is unchanged\n" \
      "${key}" "${reference}" >&2
    return 1
  fi

  # Match `sv set`, which stores one line. The macOS Keychain also returns
  # multi-line passwords hex-encoded, which would inject the wrong value.
  if [[ "${value}" == *$'\n'* ]]; then
    printf "sv: the 1Password value for %s (%s) has more than one line; sv stores single-line values\n" \
      "${key}" "${reference}" >&2
    return 1
  fi

  if ! store_set "${key}" "${value}"; then
    printf "sv: failed to store %s in the local backend\n" "${key}" >&2
    return 1
  fi
}

# Print the item titles in the configured vault, one per line.
op_list_titles() {
  local json err_file err status rest pattern
  err_file="$(mktemp)"

  if json="$(op_cli item list --vault "${SV_OP_VAULT}" --format json 2>"${err_file}")"; then
    rm -f "${err_file}"
  else
    status=$?
    err="$(<"${err_file}")"
    rm -f "${err_file}"
    die "could not list 1Password vault '${SV_OP_VAULT}': $(op_failure_detail "${status}" "${err}")"
  fi

  # A JSON string cannot contain an unescaped quote, so in valid JSON every
  # `"title":` is an object key, and only item objects have a title. Escaped
  # titles are captured raw and then rejected as invalid key names.
  pattern='"title"[[:space:]]*:[[:space:]]*"(([^"\\]|\\.)*)"'
  rest="${json}"
  while [[ "${rest}" =~ ${pattern} ]]; do
    printf "%s\n" "${BASH_REMATCH[1]}"
    rest="${rest#*"${BASH_REMATCH[0]}"}"
  done
}

# Try to fill missing required keys from 1Password before `sv exec` fails.
# Prints each key it stored on stdout. Runs only on the path that would
# otherwise fail, so successful runs never call `op`. Returns
# SV_BACKEND_FAILURE_STATUS when a stored service-account token is unreadable.
op_fetch_missing() {
  local key status

  op_fetch_enabled || return 0
  if op_prepare_auth; then
    :
  else
    return $?
  fi

  for key in "$@"; do
    printf "sv: %s is missing locally; reading it from 1Password\n" "${key}" >&2
    # Keep `op` off the child's stdin, which may carry piped input.
    if op_sync_key "${key}" </dev/null; then
      printf "sv: stored %s from 1Password\n" "${key}" >&2
      printf "%s\n" "${key}"
    else
      status=$?
      if [[ "${status}" -eq "${SV_OP_TIMEOUT_STATUS}" ]]; then
        printf "sv: op timed out; not reading the remaining missing keys from 1Password\n" >&2
        return 0
      fi
    fi
  done
}

list_contains() {
  local needle="$1" item
  shift
  for item in "$@"; do
    [[ "${item}" != "${needle}" ]] || return 0
  done
  return 1
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

doctor_select_keychain_probe() {
  local keychain_keys="$1"
  local manifest_path manifest_entries entry manifest_key stored_key

  manifest_path="$(find_manifest)"
  if [[ -n "${manifest_path}" ]]; then
    manifest_entries="$(read_manifest "${manifest_path}")"
    if [[ -n "${manifest_entries}" ]]; then
      while IFS= read -r entry; do
        manifest_key="$(manifest_entry_key "${entry}")"
        while IFS= read -r stored_key; do
          if [[ "${manifest_key}" == "${stored_key}" ]]; then
            printf "%s\n" "${manifest_key}"
            return 0
          fi
        done <<< "${keychain_keys}"
      done <<< "${manifest_entries}"
    fi
  fi

  printf "%s\n" "${keychain_keys%%$'\n'*}"
}

doctor_check_keychain() {
  local err_file err keychain_keys probe_key status

  doctor_info "backend: keychain"

  if doctor_check_cmd security "security command"; then
    err_file="$(mktemp)"
    if keychain_keys="$(kc_ls 2>"${err_file}")"; then
      doctor_ok "macOS Keychain listing is accessible"
    else
      doctor_fail "macOS Keychain listing is not accessible in this session"
      doctor_next "Retry 'sv doctor' from an interactive macOS session that can access the login Keychain."
      rm -f "${err_file}"
      return 0
    fi
    rm -f "${err_file}"

    if [[ -z "${keychain_keys}" ]]; then
      doctor_info "no sv Keychain items found; secret value-read access was not tested"
      return 0
    fi

    probe_key="$(doctor_select_keychain_probe "${keychain_keys}")"
    err_file="$(mktemp)"
    if LC_ALL=C security find-generic-password \
      -a "${SV_KEYCHAIN_ACCOUNT}" \
      -s "${SV_SERVICE_PREFIX}${probe_key}" \
      -w >/dev/null 2>"${err_file}"; then
      doctor_ok "macOS Keychain secret values are readable (checked ${probe_key})"
    else
      status=$?
      err="$(<"${err_file}")"
      err="${err//$'\n'/ }"
      if [[ -n "${err}" ]]; then
        doctor_fail "macOS Keychain metadata is accessible, but secret value reads are blocked for ${probe_key}: ${err}"
      else
        doctor_fail "macOS Keychain metadata is accessible, but secret value reads are blocked for ${probe_key}: security exited with status ${status} without an error message"
      fi
      doctor_next "Retry 'sv doctor' from an interactive macOS session that can present a Keychain authorization prompt."
      doctor_next "If the read still fails, open Keychain Access and review Access Control for '${SV_SERVICE_PREFIX}${probe_key}'."
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

doctor_manifest_key_is_available() {
  local key="$1" status

  if store_has "${key}"; then
    :
  else
    status=$?
    return "${status}"
  fi

  case "${SV_BACKEND}" in
    keychain)
      store_get "${key}" >/dev/null
      ;;
    pass)
      return 0
      ;;
  esac
}

doctor_check_manifest() {
  local manifest_path manifest_entries
  manifest_path="$(find_manifest)"

  [[ -n "${manifest_path}" ]] || return 0

  doctor_info "project manifest: ${manifest_path}"

  if [[ ${DOCTOR_FAILURES} -gt 0 ]]; then
    doctor_info "project manifest status skipped because backend checks failed"
    return 0
  fi

  manifest_entries="$(read_manifest "${manifest_path}")"
  if [[ -z "${manifest_entries}" ]]; then
    doctor_ok "project manifest has no active entries"
    return 0
  fi

  local entry key status
  local required_present=()
  local required_missing=()
  local optional_present=()
  local optional_missing=()

  while IFS= read -r entry; do
    key="$(manifest_entry_key "${entry}")"
    if manifest_entry_is_optional "${entry}"; then
      if doctor_manifest_key_is_available "${key}"; then
        optional_present+=("${key}")
      else
        status=$?
        if [[ ${status} -eq ${SV_BACKEND_FAILURE_STATUS} ]]; then
          doctor_fail "optional secret is present, but its value is not readable: ${key}"
        else
          optional_missing+=("${key}")
        fi
      fi
    else
      if doctor_manifest_key_is_available "${key}"; then
        required_present+=("${key}")
      else
        status=$?
        if [[ ${status} -eq ${SV_BACKEND_FAILURE_STATUS} ]]; then
          doctor_fail "required secret is present, but its value is not readable: ${key}"
        else
          required_missing+=("${key}")
        fi
      fi
    fi
  done <<< "${manifest_entries}"

  if [[ ${#required_missing[@]} -gt 0 ]]; then
    doctor_fail "required secrets missing: ${required_missing[*]}"
  elif [[ ${#required_present[@]} -gt 0 ]]; then
    doctor_ok "required secrets available: ${required_present[*]}"
  else
    doctor_ok "no required secrets listed"
  fi

  if [[ ${#optional_missing[@]} -gt 0 ]]; then
    doctor_info "optional secrets missing: ${optional_missing[*]}"
  fi

  if [[ ${#optional_present[@]} -gt 0 ]]; then
    doctor_ok "optional secrets available: ${optional_present[*]}"
  fi
}

# Report optional 1Password setup without calling `op`, so doctor never
# triggers an authorization prompt or a network request.
doctor_check_op() {
  local path
  path="$(command -v op 2>/dev/null || true)"

  if [[ -z "${path}" ]]; then
    doctor_info "1Password CLI: not installed (optional; needed only for sv sync and for fetching missing keys)"
    return 0
  fi

  doctor_ok "1Password CLI: ${path} (reads op://${SV_OP_VAULT}/<KEY>/${SV_OP_FIELD})"

  if [[ "${SV_OP_FETCH:-1}" == "0" ]]; then
    doctor_info "sv exec does not fetch missing keys from 1Password (SV_OP_FETCH=0)"
  fi

  if [[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
    doctor_info "1Password auth: service-account token from the environment"
    return 0
  fi

  local status=0
  store_has "${SV_OP_TOKEN_KEY}" 2>/dev/null || status=$?
  case "${status}" in
    0) doctor_info "1Password auth: service-account token stored in sv as ${SV_OP_TOKEN_KEY}" ;;
    "${SV_BACKEND_FAILURE_STATUS}") doctor_info "1Password auth: could not check for a stored ${SV_OP_TOKEN_KEY}; the local store is not accessible" ;;
    *) doctor_info "1Password auth: 1Password app integration or an op signin session" ;;
  esac
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

  doctor_check_manifest
  doctor_check_op

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

# Read manifest entries from a .secrets manifest file.
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

manifest_entry_key() {
  local entry="$1"
  if [[ "${entry}" == *\? ]]; then
    printf "%s\n" "${entry%\?}"
  else
    printf "%s\n" "${entry}"
  fi
}

manifest_entry_is_optional() {
  [[ "$1" == *\? ]]
}

is_valid_key_name() {
  [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]
}

validate_key_name() {
  local key="$1"
  if ! is_valid_key_name "${key}"; then
    die "invalid key '${key}' — must be a valid env var name (letters, digits, underscores)"
  fi
}

validate_injectable_key_name() {
  local key="$1"
  validate_key_name "${key}"
  case "${key}" in
    PATH|BASH_ENV|ENV|SHELLOPTS|BASHOPTS|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH|DYLD_FRAMEWORK_PATH)
      die "unsafe key '${key}' — process-control environment variables cannot be injected"
      ;;
  esac
}

# ─── Resolve which secrets to inject ──────────────────────────────────────────

# Resolve the exact set of secret names for one execution mode.
# Modes are manifest (default), keys (explicit names), and all (entire store).
resolve_secret_names() {
  local mode="$1" strict="$2"
  shift 2

  if [[ "${mode}" == "manifest" ]]; then
    local manifest_path
    manifest_path="$(find_manifest)"
    if [[ -z "${manifest_path}" ]]; then
      die "no .secrets manifest found; create one, use --key <KEY>, or explicitly use --all-secrets"
    fi

    local manifest_entries
    manifest_entries="$(read_manifest "${manifest_path}")"
    if [[ -z "${manifest_entries}" ]]; then
      return
    fi

    local entry key status seen_key has_required=0
    local seen_keys=()
    while IFS= read -r entry; do
      if [[ "${strict}" -eq 1 ]] || ! manifest_entry_is_optional "${entry}"; then
        has_required=1
        break
      fi
    done <<< "${manifest_entries}"

    if [[ "${has_required}" -eq 1 ]]; then
      store_require_ready
    fi

    local missing=()
    local resolved=()
    while IFS= read -r entry; do
      key="$(manifest_entry_key "${entry}")"
      validate_injectable_key_name "${key}"
      for seen_key in "${seen_keys[@]:-}"; do
        [[ "${seen_key}" != "${key}" ]] || die "duplicate manifest key: ${key}"
      done
      seen_keys+=("${key}")
      if store_has "${key}"; then
        resolved+=("${key}")
        continue
      else
        status=$?
        if [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]]; then
          if [[ "${strict}" -eq 0 ]] && manifest_entry_is_optional "${entry}"; then
            continue
          fi
          return "${status}"
        fi
      fi

      if [[ "${strict}" -eq 1 ]] || ! manifest_entry_is_optional "${entry}"; then
        missing+=("${key}")
      fi
    done <<< "${manifest_entries}"

    if [[ ${#missing[@]} -gt 0 ]]; then
      local fetched fetch_status=0 still_missing=()
      fetched="$(op_fetch_missing "${missing[@]}")" || fetch_status=$?
      [[ "${fetch_status}" -ne "${SV_BACKEND_FAILURE_STATUS}" ]] || return "${fetch_status}"
      for key in "${missing[@]}"; do
        # shellcheck disable=SC2086 # fetched holds validated key names, one per line
        if list_contains "${key}" ${fetched}; then
          resolved+=("${key}")
        else
          still_missing+=("${key}")
        fi
      done
      if [[ ${#still_missing[@]} -gt 0 ]]; then
        die "missing required secrets (listed in ${manifest_path}): ${still_missing[*]}"
      fi
    fi

    if [[ ${#resolved[@]} -gt 0 ]]; then
      printf "%s\n" "${resolved[@]}"
    fi
    return
  fi

  if [[ "${mode}" == "keys" ]]; then
    store_require_ready
    local key status
    local missing=()
    for key in "$@"; do
      if store_has "${key}"; then
        continue
      else
        status=$?
        [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]] && return "${status}"
      fi
      missing+=("${key}")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
      local fetched fetch_status=0 still_missing=()
      fetched="$(op_fetch_missing "${missing[@]}")" || fetch_status=$?
      [[ "${fetch_status}" -ne "${SV_BACKEND_FAILURE_STATUS}" ]] || return "${fetch_status}"
      for key in "${missing[@]}"; do
        # shellcheck disable=SC2086 # fetched holds validated key names, one per line
        list_contains "${key}" ${fetched} || still_missing+=("${key}")
      done
      if [[ ${#still_missing[@]} -gt 0 ]]; then
        die "missing requested secrets: ${still_missing[*]}"
      fi
    fi
    printf "%s\n" "$@"
    return
  fi

  store_require_ready
  local all_names
  if all_names="$(store_ls)"; then
    if [[ -n "${all_names}" ]]; then
      printf "%s\n" "${all_names}"
    fi
    return 0
  fi
  return "${SV_BACKEND_FAILURE_STATUS}"
}

# ─── Commands ─────────────────────────────────────────────────────────────────

cmd_set() {
  local key="${1:-}"

  [[ -z "$key" ]] && die "usage: sv set <KEY>"

  # Reject positional value argument to avoid shell history leakage
  if [[ $# -gt 1 ]]; then
    die "do not pass the value as an argument (it leaks into shell history). Use: sv set ${key}"
  fi

  validate_key_name "${key}"

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
    [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]] && return "${status}"

    die "secret not found: $key"
  fi
}

cmd_sync() {
  local key existing
  local keys=()

  for key in "$@"; do
    [[ "${key}" != -* ]] || die "unknown sv sync option: ${key} (usage: sv sync [KEY...])"
    validate_key_name "${key}"
    for existing in "${keys[@]:-}"; do
      [[ "${existing}" != "${key}" ]] || die "duplicate key: ${key}"
    done
    keys+=("${key}")
  done

  op_available || die "sv sync needs the 1Password CLI (op). Install it (macOS: brew install 1password-cli) and sign in, then retry."
  store_require_ready
  if op_prepare_auth; then
    :
  else
    return $?
  fi

  local failures=0

  if [[ ${#keys[@]} -eq 0 ]]; then
    local titles title lower duplicates valid_titles=""
    titles="$(op_list_titles)" || exit $?
    if [[ -z "${titles}" ]]; then
      printf "sv: no items found in 1Password vault '%s'\n" "${SV_OP_VAULT}" >&2
      return 0
    fi

    while IFS= read -r title; do
      if is_valid_key_name "${title}"; then
        valid_titles+="${title}"$'\n'
      else
        printf "sv: skipping 1Password item '%s': its title is not a valid key name\n" "${title}" >&2
      fi
    done <<< "${titles}"

    # 1Password matches references without regard to case, so titles that
    # differ only in case cannot be read individually.
    duplicates="$(printf "%s" "${valid_titles}" | tr '[:upper:]' '[:lower:]' | sort | uniq -d)"

    while IFS= read -r title; do
      [[ -n "${title}" ]] || continue
      lower="$(printf "%s" "${title}" | tr '[:upper:]' '[:lower:]')"
      if [[ -n "${duplicates}" ]] && printf "%s\n" "${duplicates}" | grep -qxF -- "${lower}"; then
        printf "sv: skipping %s: more than one item in vault '%s' has this title (titles match without regard to case)\n" \
          "${title}" "${SV_OP_VAULT}" >&2
        failures=$((failures + 1))
        continue
      fi
      keys+=("${title}")
    done <<< "${valid_titles}"
  fi

  local index status
  for ((index = 0; index < ${#keys[@]}; index++)); do
    key="${keys[index]}"
    if op_sync_key "${key}"; then
      printf "sv: synced %s\n" "${key}" >&2
    else
      status=$?
      failures=$((failures + 1))
      if [[ "${status}" -eq "${SV_OP_TIMEOUT_STATUS}" ]]; then
        local remaining=$(( ${#keys[@]} - index - 1 ))
        if [[ ${remaining} -gt 0 ]]; then
          printf "sv: op timed out; skipping the %d remaining key(s)\n" "${remaining}" >&2
          failures=$((failures + remaining))
        fi
        break
      fi
    fi
  done

  if [[ ${failures} -gt 0 ]]; then
    die "${failures} key(s) did not sync; their stored values are unchanged"
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
    [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]] && return "${status}"

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
  store_require_ready
  if keys="$(store_ls)"; then
    :
  else
    return $?
  fi
  if [[ -z "$keys" ]]; then
    printf "sv: no secrets stored\n" >&2
    return
  fi
  printf "%s\n" "$keys"
}

cmd_exec() {
  local mode="manifest" strict=0 saw_separator=0
  local -a explicit_keys=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --)
        saw_separator=1
        shift
        break
        ;;
      --strict)
        [[ "${strict}" -eq 0 ]] || die "duplicate exec option: --strict"
        strict=1
        shift
        ;;
      --key)
        [[ $# -ge 2 && "$2" != "--" ]] || die "--key requires a key name"
        [[ "${mode}" != "all" ]] || die "--key and --all-secrets are mutually exclusive"
        mode="keys"
        validate_injectable_key_name "$2"
        local existing
        for existing in "${explicit_keys[@]:-}"; do
          [[ "${existing}" != "$2" ]] || die "duplicate requested key: $2"
        done
        explicit_keys+=("$2")
        shift 2
        ;;
      --key=*)
        die "use '--key <KEY>', not '--key=<KEY>'"
        ;;
      --all-secrets)
        [[ "${mode}" == "manifest" ]] || die "--all-secrets cannot be combined with --key or repeated"
        mode="all"
        shift
        ;;
      --*)
        die "unknown sv exec option: $1"
        ;;
      *)
        die "sv exec requires '--' before the command"
        ;;
    esac
  done

  [[ "${saw_separator}" -eq 1 && $# -gt 0 ]] || die "usage: sv exec [--strict | --key <KEY>... | --all-secrets] -- <command> [args...]"
  [[ "${mode}" == "manifest" || "${strict}" -eq 0 ]] || die "--strict can only be used with manifest-scoped execution"

  # Collect env vars
  local names
  if [[ "${mode}" == "keys" ]]; then
    if names="$(resolve_secret_names "${mode}" "${strict}" "${explicit_keys[@]}")"; then
      :
    else
      return $?
    fi
  elif names="$(resolve_secret_names "${mode}" "${strict}")"; then
    :
  else
    return $?
  fi

  if [[ -z "$names" ]]; then
    # No secrets to inject, just run the command
    exec "$@"
  fi

  # Resolve every value before changing this shell's environment. This prevents
  # an injected process-control variable from affecting backend reads.
  local env_names=()
  local env_values=()
  while IFS= read -r key; do
    validate_injectable_key_name "${key}"
    local value
    if value="$(store_get "$key")"; then
      env_names+=("${key}")
      env_values+=("${value}")
      continue
    else
      local status=$?
      [[ "${status}" -eq "${SV_BACKEND_FAILURE_STATUS}" ]] && return "${status}"

      die "failed to resolve secret: $key"
    fi
  done <<< "$names"

  # export is a shell builtin, so values never become argv of an intermediate
  # `env` process. Only the directly exec'd child inherits them.
  local index
  for ((index = 0; index < ${#env_names[@]}; index++)); do
    export "${env_names[index]}=${env_values[index]}"
  done
  unset value env_values
  exec "$@"
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

  chmod 755 "$tmp"
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
  sv exec [--strict] -- <cmd> [args]
                             Run with secrets from the nearest .secrets manifest
  sv exec --key <KEY> [--key <KEY>...] -- <cmd> [args]
                             Run with exactly the named required secrets
  sv exec --all-secrets -- <cmd> [args]
                             Run with every stored secret (explicit legacy mode)
  sv sync [KEY...]           Copy secrets from 1Password into the local store
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
    ANTHROPIC_API_KEY?

  Normal sv exec requires a discovered manifest, injects only listed secrets,
  and fails if any required secrets are missing from the active backend.
  Optional entries
  use a trailing ? and are skipped when missing. Use sv exec --strict --
  to treat optional entries as required. An empty manifest injects nothing.

  The manifest is found by searching up from the current directory.
  Use repeatable --key for a known exact dependency that should bypass the
  project manifest. Use --all-secrets only when broad vault access is intended.

Examples:
  sv set OPENAI_API_KEY                   # prompts for value
  echo "sk-..." | sv set OPENAI_API_KEY   # pipe from stdin
  sv ls                                   # shows: OPENAI_API_KEY
  sv exec -- npm run dev                  # runs with secrets injected
  sv exec --key ANTHROPIC_API_KEY -- node reviewer.mjs
  sv exec --all-secrets -- legacy-command
  sv unlock OPENAI_API_KEY                # Linux: warm gpg-agent interactively

1Password (optional):
  Keep each secret in a 1Password vault named "sv", as an item titled with
  the key name and the value in its "password" field. Then:

    sv sync                  # copy every item in the vault
    sv sync GH_TOKEN         # copy one key, e.g. after rotating it

  When sv exec finds a required key missing, it reads that key from
  1Password once and stores it. Optional keys are never fetched. Without the
  op CLI, sv works exactly as before.

  SV_OP_VAULT and SV_OP_FIELD change the vault and field. SV_OP_FETCH=0 turns
  off the fetch in sv exec. sv stops waiting for op after
  SV_OP_TIMEOUT_SECONDS (default 60). A service-account token stored with
  'sv set OP_SERVICE_ACCOUNT_TOKEN' is passed only to op.

Agent usage:
  Agents normally use manifest-scoped sv exec and must not guess transitive
  dependencies. For a confidently known dependency, use --key so the name is
  explicit without exposing the value:

    sv exec -- npm test
    sv exec --key ANTHROPIC_API_KEY -- node scripts/reviewer.mjs

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
  sync)       cmd_sync "$@" ;;
  unlock)     cmd_unlock "$@" ;;
  rm|remove)  cmd_rm "$@" ;;
  ls|list)    cmd_ls ;;
  doctor)     cmd_doctor ;;
  exec)      cmd_exec "$@" ;;
  update)    cmd_update ;;
  version|--version|-v)
    cmd_version ;;
  help|--help|-h)
    cmd_help ;;
  *)
    die "unknown command: $cmd (try: sv help)" ;;
esac
