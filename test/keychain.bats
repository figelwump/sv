#!/usr/bin/env bats
# keychain.bats — CRUD operations on secrets via sv set/get/rm/ls

load test_helper

setup() {
  test_require_keychain
  test_kc_purge
}

teardown() {
  test_kc_purge
}

@test "sv set stores a secret via stdin pipe" {
  run bash -c "echo 'test_value_123' | '$SV_BIN' set MY_KEY"
  [ "$status" -eq 0 ]
  # Confirm it was stored using direct keychain read
  result="$(test_kc_get MY_KEY)"
  [ "$result" = "test_value_123" ]
}

@test "sv set prints confirmation on stderr" {
  result="$(echo "abc" | "$SV_BIN" set MY_KEY 2>&1 >/dev/null)"
  [[ "$result" == *"stored MY_KEY"* ]]
}

@test "sv set updates an existing secret" {
  echo "old_value" | "$SV_BIN" set MY_KEY
  echo "new_value" | "$SV_BIN" set MY_KEY
  result="$(test_kc_get MY_KEY)"
  [ "$result" = "new_value" ]
}

@test "sv get fails with TTY gate (bats captures stdout)" {
  # bats captures stdout, so stdout is not a TTY — sv get should fail
  test_kc_set MY_KEY "secret_val"
  run "$SV_BIN" get MY_KEY
  [ "$status" -ne 0 ]
  [[ "$output" == *"interactive terminal"* ]]
}

@test "sv rm removes a secret" {
  test_kc_set MY_KEY "to_delete"
  run "$SV_BIN" rm MY_KEY
  [ "$status" -eq 0 ]
  # Verify it's gone
  run test_kc_get MY_KEY
  [ "$status" -ne 0 ]
}

@test "sv rm fails for nonexistent key" {
  run "$SV_BIN" rm NONEXISTENT_KEY_XYZ
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found"* ]]
}

@test "sv ls lists stored secret names sorted" {
  test_kc_set BRAVO "b"
  test_kc_set ALPHA "a"
  test_kc_set CHARLIE "c"
  run "$SV_BIN" ls
  [ "$status" -eq 0 ]
  # Output should have all three, sorted
  [[ "$output" == *"ALPHA"* ]]
  [[ "$output" == *"BRAVO"* ]]
  [[ "$output" == *"CHARLIE"* ]]
  # Verify sort order: ALPHA should come before BRAVO
  first_line="$(echo "$output" | head -1)"
  [ "$first_line" = "ALPHA" ]
}

@test "sv ls shows message when no secrets stored" {
  run "$SV_BIN" ls
  [ "$status" -eq 0 ]
  [[ "$output" == *"no secrets stored"* ]]
}

@test "sv unlock is Linux-only on macOS" {
  run "$SV_BIN" unlock ANY_KEY
  [ "$status" -ne 0 ]
  [[ "$output" == *"sv unlock is only needed on Linux password-store"* ]]
}

@test "round-trip: set → ls → rm → verify gone" {
  echo "roundtrip_val" | "$SV_BIN" set ROUND_TRIP_KEY
  # ls should show it
  run "$SV_BIN" ls
  [[ "$output" == *"ROUND_TRIP_KEY"* ]]
  # rm it
  "$SV_BIN" rm ROUND_TRIP_KEY
  # ls should no longer show it
  run "$SV_BIN" ls
  [[ "$output" != *"ROUND_TRIP_KEY"* ]]
}

@test "sv set stores value with special characters" {
  echo 'p@$$w0rd!&"quotes' | "$SV_BIN" set SPECIAL_KEY
  result="$(test_kc_get SPECIAL_KEY)"
  [ "$result" = 'p@$$w0rd!&"quotes' ]
}

@test "sv exec distinguishes inaccessible Keychain from a missing manifest key" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
printf 'security: SecKeychainSearchCopyNext: User interaction is not allowed.\n' >&2
exit 1
EOF
  chmod +x "${fakebin}/security"
  echo "REQUIRED_KEY" > "${project}/.secrets"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' exec -- echo should_not_run"
  [ "$status" -eq 2 ]
  [[ "$output" == *"Keychain may be inaccessible in this session"* ]]
  [[ "$output" != *"missing required secrets"* ]]
  rm -rf "${root}"
}

@test "sv exec distinguishes inaccessible Keychain enumeration from an empty vault" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
printf 'security: SecKeychainCopyDefault: A required entitlement is missing.\n' >&2
exit 1
EOF
  chmod +x "${fakebin}/security"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' exec --all-secrets -- echo should_not_run"
  [ "$status" -eq 2 ]
  [[ "$output" == *"Keychain may be inaccessible in this session"* ]]
  rm -rf "${root}"
}

@test "sv exec propagates Keychain failure while reading a resolved key" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
case " $* " in
  *" -w "*)
    printf 'security: SecKeychainSearchCopyNext: User interaction is not allowed.\n' >&2
    exit 1
    ;;
  *)
    exit 0
    ;;
esac
EOF
  chmod +x "${fakebin}/security"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' exec --key RESOLVED_KEY -- echo should_not_run"
  [ "$status" -eq 2 ]
  [[ "$output" == *"Keychain may be inaccessible in this session"* ]]
  [[ "$output" != *"failed to resolve secret"* ]]
  rm -rf "${root}"
}

@test "sv ls handles a literal service prefix with regex and path characters" {
  local prefix='sv_test.literal.[x]/*:'
  security add-generic-password -a "${USER}" -s "${prefix}BRAVO" -w "b" -U >/dev/null 2>&1
  security add-generic-password -a "${USER}" -s "${prefix}ALPHA" -w "a" -U >/dev/null 2>&1

  run env SV_SERVICE_PREFIX="${prefix}" "$SV_BIN" ls
  [ "$status" -eq 0 ]
  [ "$output" = $'ALPHA\nBRAVO' ]

  security delete-generic-password -a "${USER}" -s "${prefix}ALPHA" >/dev/null 2>&1 || true
  security delete-generic-password -a "${USER}" -s "${prefix}BRAVO" >/dev/null 2>&1 || true
}

@test "sv exec accepts the C-locale missing-item message fallback" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
printf 'security: The specified item could not be found in the keychain.\n' >&2
exit 1
EOF
  chmod +x "${fakebin}/security"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' exec --key ABSENT_KEY -- echo should_not_run"
  [ "$status" -eq 1 ]
  [[ "$output" == *"missing requested secrets: ABSENT_KEY"* ]]
  [[ "$output" != *"Keychain may be inaccessible"* ]]
  rm -rf "${root}"
}

@test "optional-only manifest runs when Keychain access is unavailable" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
printf 'security: User interaction is not allowed.\n' >&2
exit 1
EOF
  chmod +x "${fakebin}/security"
  echo "OPTIONAL_KEY?" > "${project}/.secrets"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' exec -- echo optional_backend_unavailable_ok"
  [ "$status" -eq 0 ]
  [[ "$output" == *"optional_backend_unavailable_ok"* ]]
  rm -rf "${root}"
}
