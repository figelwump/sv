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
#   sv unlock <KEY>            Unlock Linux GPG agent without printing a secret
#   sv doctor                  Check backend setup and common failures
#   sv update                  Update sv to the latest version
#   sv version                 Print version
#   sv help                    Show this help
#

set -euo pipefail

readonly SV_VERSION="0.2.0"
readonly SV_REPO="figelwump/sv"
readonly SV_RAW_URL="https://raw.githubusercontent.com/${SV_REPO}/main/sv"
readonly SV_SERVICE_PREFIX="${SV_SERVICE_PREFIX:-sv:}"
readonly SV_KEYCHAIN_ACCOUNT="${USER}"
readonly SV_MANIFEST=".secrets"
readonly SV_PASS_NAMESPACE="sv"
readonly SV_BACKEND_FAILURE_STATUS=2
readonly SV_PASS_TIMEOUT_SECONDS="${SV_PASS_TIMEOUT_SECONDS:-8}"

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

validate_key_name() {
  local key="$1"
  if [[ ! "${key}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
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
      die "missing required secrets (listed in ${manifest_path}): ${missing[*]}"
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
      die "missing requested secrets: ${missing[*]}"
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
