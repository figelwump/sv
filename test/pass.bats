#!/usr/bin/env bats
# pass.bats — CRUD operations on secrets via sv on Linux password-store

load test_helper

setup_file() {
  test_backend_setup_file
}

teardown_file() {
  test_backend_teardown_file
}

setup() {
  test_require_pass
  test_source_pass_env
  test_pass_purge
}

teardown() {
  test_source_pass_env
  test_pass_purge
}

@test "sv set stores a secret in password-store via stdin pipe" {
  run bash -c "echo 'test_value_123' | '$SV_BIN' set MY_KEY"
  [ "$status" -eq 0 ]
  result="$(test_pass_get MY_KEY)"
  [ "$result" = "test_value_123" ]
}

@test "sv set updates an existing secret in password-store" {
  echo "old_value" | "$SV_BIN" set MY_KEY
  echo "new_value" | "$SV_BIN" set MY_KEY
  result="$(test_pass_get MY_KEY)"
  [ "$result" = "new_value" ]
}

@test "sv rm removes a password-store secret" {
  test_pass_set MY_KEY "to_delete"
  run "$SV_BIN" rm MY_KEY
  [ "$status" -eq 0 ]
  run test_pass_get MY_KEY
  [ "$status" -ne 0 ]
}

@test "sv rm fails for nonexistent password-store secret" {
  run "$SV_BIN" rm NONEXISTENT_KEY_XYZ
  [ "$status" -ne 0 ]
  [[ "$output" == *"not found"* ]]
}

@test "sv ls lists stored secret names from password-store" {
  test_pass_set BRAVO "b"
  test_pass_set ALPHA "a"
  test_pass_set CHARLIE "c"
  run "$SV_BIN" ls
  [ "$status" -eq 0 ]
  [ "$output" = $'ALPHA\nBRAVO\nCHARLIE' ]
}

@test "sv ls shows message when password-store namespace is empty" {
  run "$SV_BIN" ls
  [ "$status" -eq 0 ]
  [[ "$output" == *"no secrets stored"* ]]
}

@test "sv unlock requires a key" {
  run "$SV_BIN" unlock
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage: sv unlock <KEY>"* ]]
}

@test "sv unlock requires an interactive terminal" {
  test_pass_set UNLOCK_KEY "secret_unlock_value"

  run "$SV_BIN" unlock UNLOCK_KEY
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires an interactive terminal"* ]]
  [[ "$output" == *"ask the human user"* ]]
  [[ "$output" != *"secret_unlock_value"* ]]
}

@test "sv unlock warms gpg-agent without printing the secret" {
  command -v script >/dev/null 2>&1 || skip "script command not found"
  test_pass_set UNLOCK_KEY "secret_unlock_value"

  run script -q -e -c "export PASSWORD_STORE_DIR='$PASSWORD_STORE_DIR' GNUPGHOME='$GNUPGHOME' SV_SERVICE_PREFIX='$SV_SERVICE_PREFIX'; '$SV_BIN' unlock UNLOCK_KEY" /dev/null
  [ "$status" -eq 0 ]
  [[ "$output" == *"unlocked Linux password store for UNLOCK_KEY"* ]]
  [[ "$output" != *"secret_unlock_value"* ]]
}

@test "sv set requires an initialized password-store" {
  local empty_store
  empty_store="$(mktemp -d)"

  run bash -c "export PASSWORD_STORE_DIR='$empty_store' GNUPGHOME='$GNUPGHOME'; echo val | '$SV_BIN' set MY_KEY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"password store is not initialized"* ]]

  rm -rf "$empty_store"
}

@test "sv exec without a manifest still runs when password-store is uninitialized" {
  local empty_store
  empty_store="$(mktemp -d)"

  run bash -c "export PASSWORD_STORE_DIR='$empty_store' GNUPGHOME='$GNUPGHOME'; '$SV_BIN' exec -- echo pass_through"
  [ "$status" -eq 0 ]
  [ "$output" = "pass_through" ]

  rm -rf "$empty_store"
}

@test "sv exec with a manifest fails clearly when password-store is uninitialized" {
  local empty_store manifest_dir
  empty_store="$(mktemp -d)"
  manifest_dir="$(mktemp -d)"
  echo "MY_KEY" > "${manifest_dir}/.secrets"

  run bash -c "cd '$manifest_dir' && export PASSWORD_STORE_DIR='$empty_store' GNUPGHOME='$GNUPGHOME'; '$SV_BIN' exec -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"password store is not initialized"* ]]

  rm -rf "$empty_store" "$manifest_dir"
}

@test "sv exec reports locked gpg-agent with human unlock instruction once" {
  local root fakebin store_dir manifest_dir
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  store_dir="${root}/store"
  manifest_dir="${root}/project"
  mkdir -p "${fakebin}" "${store_dir}/sv" "${manifest_dir}"
  echo "${TEST_GPG_ID}" > "${store_dir}/.gpg-id"
  : > "${store_dir}/sv/LOCKED_KEY;PWNED.gpg"
  echo "LOCKED_KEY;PWNED" > "${manifest_dir}/.secrets"

  cat > "${fakebin}/pass" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "show" ]]; then
  printf "%s\n" "${FAKE_PASS_ERROR:-fake pass failure}" >&2
  exit 1
fi
printf "unexpected pass call: %s\n" "$*" >&2
exit 1
EOF
  chmod +x "${fakebin}/pass"

  run bash -c "cd '$manifest_dir' && export PATH='$fakebin':\$PATH PASSWORD_STORE_DIR='$store_dir' GNUPGHOME='$GNUPGHOME' FAKE_PASS_ERROR='gpg: public key decryption failed: Inappropriate ioctl for device'; '$SV_BIN' exec -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"failed to read LOCKED_KEY;PWNED"* ]]
  [[ "$output" == *"gpg-agent is locked or cannot prompt"* ]]
  [[ "$output" == *"ask the human user"* ]]
  printf "%s" "$output" | grep -F "sv unlock LOCKED_KEY\\;PWNED" >/dev/null
  [[ "$output" != *"sv unlock LOCKED_KEY;PWNED"* ]]
  [[ "$output" != *"failed to resolve secret"* ]]

  rm -rf "$root"
}

@test "sv exec preserves unrecognized password-store errors" {
  local root fakebin store_dir manifest_dir
  root="$(mktemp -d)"
  fakebin="${root}/bin"
  store_dir="${root}/store"
  manifest_dir="${root}/project"
  mkdir -p "${fakebin}" "${store_dir}/sv" "${manifest_dir}"
  echo "${TEST_GPG_ID}" > "${store_dir}/.gpg-id"
  : > "${store_dir}/sv/ODD_KEY.gpg"
  echo "ODD_KEY" > "${manifest_dir}/.secrets"

  cat > "${fakebin}/pass" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "show" ]]; then
  printf "%s\n" "${FAKE_PASS_ERROR:-fake pass failure}" >&2
  exit 1
fi
printf "unexpected pass call: %s\n" "$*" >&2
exit 1
EOF
  chmod +x "${fakebin}/pass"

  run bash -c "cd '$manifest_dir' && export PATH='$fakebin':\$PATH PASSWORD_STORE_DIR='$store_dir' GNUPGHOME='$GNUPGHOME' FAKE_PASS_ERROR='gpg: decryption failed: Bad session key'; '$SV_BIN' exec -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"failed to read ODD_KEY from the Linux password store: gpg: decryption failed: Bad session key"* ]]
  [[ "$output" != *"ask the human user"* ]]
  [[ "$output" != *"failed to resolve secret"* ]]

  rm -rf "$root"
}

@test "sv doctor reports pass backend health" {
  run bash -c "export PASSWORD_STORE_DIR='$PASSWORD_STORE_DIR' GNUPGHOME='$GNUPGHOME'; '$SV_BIN' doctor"
  [ "$status" -eq 0 ]
  [[ "$output" == *"backend: pass"* ]]
  [[ "$output" == *"password store initialized"* ]]
}

@test "sv doctor fails clearly when password-store is uninitialized" {
  local empty_store
  empty_store="$(mktemp -d)"

  run bash -c "export PASSWORD_STORE_DIR='$empty_store' GNUPGHOME='$GNUPGHOME'; '$SV_BIN' doctor"
  [ "$status" -ne 0 ]
  [[ "$output" == *"password store not initialized"* ]]
  [[ "$output" == *"Next steps:"* ]]
  [[ "$output" == *"gpg --full-generate-key"* ]]
  [[ "$output" == *"gpg --list-secret-keys --keyid-format=long"* ]]
  [[ "$output" == *"pass init <gpg-id>"* ]]

  rm -rf "$empty_store"
}

@test "sv doctor warnings still exit successfully" {
  GNUPGHOME="$GNUPGHOME" gpgconf --kill gpg-agent >/dev/null 2>&1 || true

  run bash -c "export PASSWORD_STORE_DIR='$PASSWORD_STORE_DIR' GNUPGHOME='$GNUPGHOME'; '$SV_BIN' doctor"
  [ "$status" -eq 0 ]
  [[ "$output" == *"[warn]"* ]]
  [[ "$output" == *"sv doctor: ok with"* ]]

  GNUPGHOME="$GNUPGHOME" gpgconf --launch gpg-agent >/dev/null 2>&1 || true
}
