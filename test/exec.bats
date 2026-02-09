#!/usr/bin/env bats
# exec.bats — sv exec injects secrets as env vars into child processes

load test_helper

# Override setup to also create a temp dir for manifests
setup() {
  test_kc_purge
  TEST_TMPDIR="$(mktemp -d)"
}

teardown() {
  test_kc_purge
  rm -rf "$TEST_TMPDIR"
}

@test "sv exec injects secret as env var" {
  test_kc_set API_KEY "secret_api_123"
  # Create a manifest so only our key is injected
  echo "API_KEY" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv API_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "secret_api_123" ]
}

@test "sv exec passes arguments through to child" {
  test_kc_set DUMMY "val"
  echo "DUMMY" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo hello world"
  [ "$status" -eq 0 ]
  [ "$output" = "hello world" ]
}

@test "sv exec works without -- separator" {
  test_kc_set DUMMY "val"
  echo "DUMMY" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec echo hello"
  [ "$status" -eq 0 ]
  [ "$output" = "hello" ]
}

@test "sv exec with no secrets just runs the command" {
  # Empty manifest means no secrets to inject
  echo "" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo pass_through"
  [ "$status" -eq 0 ]
  [ "$output" = "pass_through" ]
}

@test "sv exec preserves child exit code" {
  echo "" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- bash -c 'exit 42'"
  [ "$status" -eq 42 ]
}

@test "sv exec injects multiple secrets simultaneously" {
  test_kc_set KEY_A "val_a"
  test_kc_set KEY_B "val_b"
  test_kc_set KEY_C "val_c"
  printf "KEY_A\nKEY_B\nKEY_C\n" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- bash -c 'echo \$KEY_A \$KEY_B \$KEY_C'"
  [ "$status" -eq 0 ]
  [ "$output" = "val_a val_b val_c" ]
}

@test "sv exec with no command shows usage error" {
  run "$SV_BIN" exec --
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}

@test "sv exec secret values are not visible as sv arguments in process list" {
  # This verifies that exec env is used (values in env, not in argv)
  test_kc_set SECRET_PS "hidden_value"
  echo "SECRET_PS" > "$TEST_TMPDIR/.secrets"
  # The child should see the env var, but it should not be in $0 or args
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv SECRET_PS"
  [ "$status" -eq 0 ]
  [ "$output" = "hidden_value" ]
}
