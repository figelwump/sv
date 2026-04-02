# test_helper.bash — shared setup/teardown and backend helpers for sv tests

export SV_SERVICE_PREFIX="sv_test:"

# Resolve the path to the sv script under test
SV_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sv"

test_backend() {
  case "$(uname -s)" in
    Darwin) printf "keychain\n" ;;
    Linux) printf "pass\n" ;;
    *) printf "unsupported\n" ;;
  esac
}

test_pass_env_file() {
  local base_dir
  base_dir="${BATS_FILE_TMPDIR:-/tmp}"
  printf "%s/pass-test.env\n" "${base_dir}"
}

test_require_keychain() {
  [[ "$(test_backend)" == "keychain" ]] || skip "keychain tests require macOS"
  command -v security >/dev/null 2>&1 || skip "security command not found"
}

test_require_pass() {
  [[ "$(test_backend)" == "pass" ]] || skip "pass tests require Linux"
  command -v pass >/dev/null 2>&1 || skip "pass command not found"
  command -v gpg >/dev/null 2>&1 || skip "gpg command not found"
}

test_backend_setup_file() {
  case "$(test_backend)" in
    keychain)
      return
      ;;
    pass)
      if ! command -v pass >/dev/null 2>&1 || ! command -v gpg >/dev/null 2>&1; then
        return
      fi

      local env_file root gnupg_home store_dir batch_file key_id
      env_file="$(test_pass_env_file)"

      if [[ -f "${env_file}" ]]; then
        # shellcheck disable=SC1090
        source "${env_file}"
        if [[ -d "${TEST_BACKEND_ROOT}" ]]; then
          return
        fi
        rm -f "${env_file}"
      fi

      root="$(mktemp -d "/tmp/sv-pass-test-$(basename "${BATS_TEST_FILENAME:-sv-tests}" .bats)-XXXXXX")"
      gnupg_home="${root}/gnupg"
      store_dir="${root}/store"
      batch_file="${root}/gpg-batch"

      mkdir -p "${gnupg_home}" "${store_dir}"
      chmod 700 "${gnupg_home}"

      cat > "${gnupg_home}/gpg-agent.conf" <<'EOF'
allow-loopback-pinentry
EOF

      cat > "${batch_file}" <<'EOF'
%no-protection
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: sv test
Name-Email: sv-test@example.com
Expire-Date: 0
%commit
EOF

      GNUPGHOME="${gnupg_home}" gpgconf --launch gpg-agent >/dev/null 2>&1 || true
      GNUPGHOME="${gnupg_home}" gpg --batch --generate-key "${batch_file}" >/dev/null 2>&1
      key_id="$(GNUPGHOME="${gnupg_home}" gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "sec" { print $5; exit }')"

      PASSWORD_STORE_DIR="${store_dir}" GNUPGHOME="${gnupg_home}" pass init "${key_id}" >/dev/null 2>&1

      cat > "${env_file}" <<EOF
TEST_BACKEND_ROOT='${root}'
GNUPGHOME='${gnupg_home}'
PASSWORD_STORE_DIR='${store_dir}'
TEST_GPG_ID='${key_id}'
EOF
      chmod 600 "${env_file}"
      ;;
  esac
}

test_backend_teardown_file() {
  case "$(test_backend)" in
    keychain)
      return
      ;;
    pass)
      local env_file
      env_file="$(test_pass_env_file)"

      if [[ -f "${env_file}" ]]; then
        # shellcheck disable=SC1090
        source "${env_file}"
        GNUPGHOME="${GNUPGHOME}" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
        rm -rf "${TEST_BACKEND_ROOT}"
        rm -f "${env_file}"
      fi
      ;;
  esac
}

test_source_pass_env() {
  local env_file
  env_file="$(test_pass_env_file)"

  if [[ ! -f "${env_file}" ]]; then
    test_backend_setup_file
  fi

  # shellcheck disable=SC1090
  source "${env_file}"
  export TEST_BACKEND_ROOT GNUPGHOME PASSWORD_STORE_DIR TEST_GPG_ID
}

# ─── Direct backend helpers (bypass sv so bugs in sv don't break fixtures) ───

test_kc_set() {
  local key="$1" value="$2"
  security add-generic-password \
    -a "${USER}" \
    -s "${SV_SERVICE_PREFIX}${key}" \
    -w "${value}" \
    -U 2>/dev/null
}

test_kc_get() {
  local key="$1"
  security find-generic-password \
    -a "${USER}" \
    -s "${SV_SERVICE_PREFIX}${key}" \
    -w 2>/dev/null
}

test_kc_rm() {
  local key="$1"
  security delete-generic-password \
    -a "${USER}" \
    -s "${SV_SERVICE_PREFIX}${key}" >/dev/null 2>&1 || true
}

test_kc_purge() {
  local keys
  keys="$(security dump-keychain 2>/dev/null \
    | grep "\"svce\"<blob>=\"${SV_SERVICE_PREFIX}" \
    | sed "s/.*\"${SV_SERVICE_PREFIX}\(.*\)\"/\1/" \
    | sort -u)" || true
  if [[ -n "$keys" ]]; then
    while IFS= read -r key; do
      test_kc_rm "$key"
    done <<< "$keys"
  fi
}

test_pass_path() {
  local key="$1"
  printf "sv/%s\n" "${key}"
}

test_pass_set() {
  local key="$1" value="$2"
  printf "%s\n" "${value}" | pass insert --multiline --force "$(test_pass_path "$key")" >/dev/null
}

test_pass_get() {
  local key="$1"
  pass show "$(test_pass_path "$key")" 2>/dev/null
}

test_pass_rm() {
  local key="$1"
  pass rm --force "$(test_pass_path "$key")" >/dev/null 2>&1 || true
}

test_pass_purge() {
  rm -rf "${PASSWORD_STORE_DIR}/sv"
}

test_store_set() {
  case "$(test_backend)" in
    keychain) test_kc_set "$@" ;;
    pass)
      test_source_pass_env
      test_pass_set "$@"
      ;;
  esac
}

test_store_get() {
  case "$(test_backend)" in
    keychain) test_kc_get "$1" ;;
    pass)
      test_source_pass_env
      test_pass_get "$1"
      ;;
  esac
}

test_store_rm() {
  case "$(test_backend)" in
    keychain) test_kc_rm "$1" ;;
    pass)
      test_source_pass_env
      test_pass_rm "$1"
      ;;
  esac
}

test_store_purge() {
  case "$(test_backend)" in
    keychain) test_kc_purge ;;
    pass)
      test_source_pass_env
      test_pass_purge
      ;;
  esac
}

# ─── Standard bats setup/teardown ────────────────────────────────────────────

setup() {
  case "$(test_backend)" in
    keychain)
      test_require_keychain
      ;;
    pass)
      test_require_pass
      test_source_pass_env
      ;;
    *)
      skip "unsupported OS for sv tests"
      ;;
  esac

  test_store_purge
}

teardown() {
  case "$(test_backend)" in
    pass)
      test_source_pass_env
      ;;
  esac

  test_store_purge
}
