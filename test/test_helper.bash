# test_helper.bash — shared setup/teardown and keychain helpers for sv tests
#
# Every test file should: load test_helper
# This gives each test an isolated keychain namespace (sv_test:) and cleanup.

export SV_SERVICE_PREFIX="sv_test:"

# Resolve the path to the sv script under test
SV_BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/sv"

# ─── Direct keychain helpers (bypass sv so bugs in sv don't break fixtures) ───

# Store a value directly in the keychain under the test prefix.
test_kc_set() {
  local key="$1" value="$2"
  security add-generic-password \
    -a "${USER}" \
    -s "${SV_SERVICE_PREFIX}${key}" \
    -w "${value}" \
    -U 2>/dev/null
}

# Read a value directly from the keychain under the test prefix.
test_kc_get() {
  local key="$1"
  security find-generic-password \
    -a "${USER}" \
    -s "${SV_SERVICE_PREFIX}${key}" \
    -w 2>/dev/null
}

# Remove a single test keychain entry.
test_kc_rm() {
  local key="$1"
  security delete-generic-password \
    -a "${USER}" \
    -s "${SV_SERVICE_PREFIX}${key}" >/dev/null 2>&1 || true
}

# Purge ALL sv_test:* keychain entries.
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

# ─── Standard bats setup/teardown ────────────────────────────────────────────

setup() {
  # Purge before each test for a clean slate
  test_kc_purge
}

teardown() {
  # Purge after each test to avoid leakage
  test_kc_purge
}
