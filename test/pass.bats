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
