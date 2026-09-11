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

@test "sv ls works with the macOS system Bash" {
  test_kc_set SYSTEM_BASH_KEY "value"

  run /bin/bash "$SV_BIN" ls
  [ "$status" -eq 0 ]
  [ "$output" = "SYSTEM_BASH_KEY" ]
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

@test "sv doctor fails when Keychain metadata is accessible but value reads are blocked" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  dump-keychain)
    printf '    "svce"<blob>="sv_test:BLOCKED_KEY"\n'
    ;;
  find-generic-password)
    printf 'security: SecKeychainSearchCopyNext: User interaction is not allowed.\n' >&2
    exit 1
    ;;
esac
EOF
  chmod +x "${fakebin}/security"
  echo "BLOCKED_KEY" > "${project}/.secrets"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' doctor"
  [ "$status" -eq 1 ]
  [[ "$output" == *"macOS Keychain listing is accessible"* ]]
  [[ "$output" == *"metadata is accessible, but secret value reads are blocked for BLOCKED_KEY"* ]]
  [[ "$output" == *"project manifest status skipped because backend checks failed"* ]]
  [[ "$output" != *"required secrets available"* ]]
  [[ "$output" == *"review Access Control for 'sv_test:BLOCKED_KEY'"* ]]
  rm -rf "${root}"
}

@test "sv doctor discards a successful Keychain value read" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  dump-keychain)
    printf '    "svce"<blob>="sv_test:ALPHA_OTHER_KEY"\n'
    printf '    "svce"<blob>="sv_test:READABLE_KEY"\n'
    ;;
  find-generic-password)
    case " $* " in
      *" -s sv_test:READABLE_KEY "*)
        case " $* " in
          *" -w "*) printf 'doctor_probe_secret_value\n' ;;
        esac
        ;;
      *)
        printf 'doctor selected a non-manifest Keychain item\n' >&2
        exit 9
        ;;
    esac
    ;;
esac
EOF
  chmod +x "${fakebin}/security"
  echo "READABLE_KEY" > "${project}/.secrets"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' doctor"
  [ "$status" -eq 0 ]
  [[ "$output" == *"macOS Keychain secret values are readable (checked READABLE_KEY)"* ]]
  [[ "$output" == *"required secrets available: READABLE_KEY"* ]]
  [[ "$output" != *"doctor_probe_secret_value"* ]]
  [[ "$output" != *"doctor selected a non-manifest Keychain item"* ]]
  rm -rf "${root}"
}

@test "sv doctor validates each present manifest Keychain value" {
  local root fakebin project
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  project="${root}/project"
  mkdir -p "${fakebin}" "${project}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  dump-keychain)
    printf '    "svce"<blob>="sv_test:READABLE_KEY"\n'
    printf '    "svce"<blob>="sv_test:BLOCKED_KEY"\n'
    ;;
  find-generic-password)
    case " $* " in
      *" -s sv_test:READABLE_KEY "*)
        case " $* " in
          *" -w "*) printf 'readable_secret_value\n' ;;
        esac
        ;;
      *" -s sv_test:BLOCKED_KEY "*)
        case " $* " in
          *" -w "*)
            printf 'security: SecKeychainSearchCopyNext: User interaction is not allowed.\n' >&2
            exit 1
            ;;
        esac
        ;;
      *)
        printf 'unexpected Keychain item\n' >&2
        exit 9
        ;;
    esac
    ;;
esac
EOF
  chmod +x "${fakebin}/security"
  printf "READABLE_KEY\nBLOCKED_KEY\n" > "${project}/.secrets"

  run bash -c "cd '$project' && PATH='$fakebin':\$PATH '$SV_BIN' doctor"
  [ "$status" -eq 1 ]
  [[ "$output" == *"macOS Keychain secret values are readable (checked READABLE_KEY)"* ]]
  [[ "$output" == *"required secret is present, but its value is not readable: BLOCKED_KEY"* ]]
  [[ "$output" == *"required secrets available: READABLE_KEY"* ]]
  [[ "$output" != *"required secrets available: READABLE_KEY BLOCKED_KEY"* ]]
  [[ "$output" != *"readable_secret_value"* ]]
  rm -rf "${root}"
}

@test "sv doctor reports that an empty Keychain cannot exercise a value read" {
  local root fakebin
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  mkdir -p "${fakebin}"
  cat > "${fakebin}/security" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  dump-keychain)
    exit 0
    ;;
  *)
    printf 'unexpected Keychain value-read probe\n' >&2
    exit 9
    ;;
esac
EOF
  chmod +x "${fakebin}/security"

  run env PATH="${fakebin}:${PATH}" "$SV_BIN" doctor
  [ "$status" -eq 0 ]
  [[ "$output" == *"no sv Keychain items found; secret value-read access was not tested"* ]]
  [[ "$output" != *"unexpected Keychain value-read probe"* ]]
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
