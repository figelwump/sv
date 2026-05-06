#!/usr/bin/env bats
# manifest.bats — .secrets manifest finding, parsing, scoping

load test_helper

setup_file() {
  test_backend_setup_file
}

teardown_file() {
  test_backend_teardown_file
}

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
  TEST_TMPDIR="$(mktemp -d)"
}

teardown() {
  test_store_purge
  rm -rf "$TEST_TMPDIR"
}

@test "manifest scopes injection to only listed secrets" {
  test_store_set LISTED_KEY "listed_val"
  test_store_set UNLISTED_KEY "unlisted_val"
  echo "LISTED_KEY" > "$TEST_TMPDIR/.secrets"
  # LISTED_KEY should be injected
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv LISTED_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "listed_val" ]
  # UNLISTED_KEY should NOT be injected
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv UNLISTED_KEY"
  [ "$status" -ne 0 ]
}

@test "manifest is found in parent directory" {
  test_store_set PARENT_KEY "parent_val"
  echo "PARENT_KEY" > "$TEST_TMPDIR/.secrets"
  mkdir -p "$TEST_TMPDIR/subdir/deep"
  run bash -c "cd '$TEST_TMPDIR/subdir/deep' && '$SV_BIN' exec -- printenv PARENT_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "parent_val" ]
}

@test "manifest fails on missing required secret" {
  # Manifest lists a key that doesn't exist in keychain
  echo "DOES_NOT_EXIST" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing required secrets"* ]]
  [[ "$output" == *"DOES_NOT_EXIST"* ]]
}

@test "manifest skips missing optional secret" {
  test_store_set REQUIRED_KEY "required_val"
  printf "REQUIRED_KEY\nOPTIONAL_KEY?\n" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- bash -c 'printf \"%s:%s\" \"\$REQUIRED_KEY\" \"\${OPTIONAL_KEY-unset}\"'"
  [ "$status" -eq 0 ]
  [ "$output" = "required_val:unset" ]
}

@test "manifest injects optional secret when present" {
  test_store_set OPTIONAL_KEY "optional_val"
  echo "OPTIONAL_KEY?" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv OPTIONAL_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "optional_val" ]
}

@test "sv exec strict treats optional secret as required" {
  echo "OPTIONAL_KEY?" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --strict -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing required secrets"* ]]
  [[ "$output" == *"OPTIONAL_KEY"* ]]
}

@test "sv doctor reports required and optional manifest status separately" {
  test_store_set PRESENT_REQUIRED "required_val"
  test_store_set PRESENT_OPTIONAL "optional_val"
  printf "PRESENT_REQUIRED\nMISSING_REQUIRED\nPRESENT_OPTIONAL?\nMISSING_OPTIONAL?\n" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' doctor"
  [ "$status" -ne 0 ]
  [[ "$output" == *"required secrets missing: MISSING_REQUIRED"* ]]
  [[ "$output" == *"optional secrets missing: MISSING_OPTIONAL"* ]]
  [[ "$output" == *"optional secrets available: PRESENT_OPTIONAL"* ]]
}

@test "empty manifest injects nothing, just runs command" {
  test_store_set SOME_KEY "some_val"
  # Manifest exists but is empty
  touch "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo ran_ok"
  [ "$status" -eq 0 ]
  [ "$output" = "ran_ok" ]
}

@test "comments-only manifest injects nothing" {
  test_store_set SOME_KEY "some_val"
  cat > "$TEST_TMPDIR/.secrets" <<'EOF'
# This is a comment
# Another comment

EOF
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo ran_ok"
  [ "$status" -eq 0 ]
  [ "$output" = "ran_ok" ]
}

@test "manifest trims whitespace around key names" {
  test_store_set TRIMMED_KEY "trimmed_val"
  # Key with leading/trailing whitespace
  printf "  TRIMMED_KEY  \n" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv TRIMMED_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "trimmed_val" ]
}

@test "no manifest injects all secrets" {
  test_store_set ALL_KEY_A "val_a"
  test_store_set ALL_KEY_B "val_b"
  # No .secrets file — should inject everything
  mkdir -p "$TEST_TMPDIR/no_manifest"
  run bash -c "cd '$TEST_TMPDIR/no_manifest' && '$SV_BIN' exec -- bash -c 'echo \$ALL_KEY_A \$ALL_KEY_B'"
  [ "$status" -eq 0 ]
  [ "$output" = "val_a val_b" ]
}

@test "manifest with mixed content: comments, blanks, and valid keys" {
  test_store_set REAL_KEY "real_val"
  cat > "$TEST_TMPDIR/.secrets" <<'EOF'
# comment at top

REAL_KEY

# trailing comment
EOF
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv REAL_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "real_val" ]
}
