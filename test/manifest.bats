#!/usr/bin/env bats
# manifest.bats — .secrets manifest finding, parsing, scoping

load test_helper

setup() {
  test_kc_purge
  TEST_TMPDIR="$(mktemp -d)"
}

teardown() {
  test_kc_purge
  rm -rf "$TEST_TMPDIR"
}

@test "manifest scopes injection to only listed secrets" {
  test_kc_set LISTED_KEY "listed_val"
  test_kc_set UNLISTED_KEY "unlisted_val"
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
  test_kc_set PARENT_KEY "parent_val"
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

@test "empty manifest injects nothing, just runs command" {
  test_kc_set SOME_KEY "some_val"
  # Manifest exists but is empty
  touch "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo ran_ok"
  [ "$status" -eq 0 ]
  [ "$output" = "ran_ok" ]
}

@test "comments-only manifest injects nothing" {
  test_kc_set SOME_KEY "some_val"
  cat > "$TEST_TMPDIR/.secrets" <<'EOF'
# This is a comment
# Another comment

EOF
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo ran_ok"
  [ "$status" -eq 0 ]
  [ "$output" = "ran_ok" ]
}

@test "manifest trims whitespace around key names" {
  test_kc_set TRIMMED_KEY "trimmed_val"
  # Key with leading/trailing whitespace
  printf "  TRIMMED_KEY  \n" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv TRIMMED_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "trimmed_val" ]
}

@test "no manifest injects all secrets" {
  test_kc_set ALL_KEY_A "val_a"
  test_kc_set ALL_KEY_B "val_b"
  # No .secrets file — should inject everything
  mkdir -p "$TEST_TMPDIR/no_manifest"
  run bash -c "cd '$TEST_TMPDIR/no_manifest' && '$SV_BIN' exec -- bash -c 'echo \$ALL_KEY_A \$ALL_KEY_B'"
  [ "$status" -eq 0 ]
  [ "$output" = "val_a val_b" ]
}

@test "manifest with mixed content: comments, blanks, and valid keys" {
  test_kc_set REAL_KEY "real_val"
  cat > "$TEST_TMPDIR/.secrets" <<'EOF'
# comment at top

REAL_KEY

# trailing comment
EOF
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv REAL_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "real_val" ]
}
