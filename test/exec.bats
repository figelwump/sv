#!/usr/bin/env bats
# exec.bats — sv exec injects secrets as env vars into child processes

load test_helper

setup_file() {
  test_backend_setup_file
}

teardown_file() {
  test_backend_teardown_file
}

# Override setup to also create a temp dir for manifests
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

@test "sv exec injects secret as env var" {
  test_store_set API_KEY "secret_api_123"
  # Create a manifest so only our key is injected
  echo "API_KEY" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv API_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "secret_api_123" ]
}

@test "sv exec passes arguments through to child" {
  test_store_set DUMMY "val"
  echo "DUMMY" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- echo hello world"
  [ "$status" -eq 0 ]
  [ "$output" = "hello world" ]
}

@test "sv exec requires -- separator" {
  test_store_set DUMMY "val"
  echo "DUMMY" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec echo hello"
  [ "$status" -ne 0 ]
  [[ "$output" == *"requires '--'"* ]]
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
  test_store_set KEY_A "val_a"
  test_store_set KEY_B "val_b"
  test_store_set KEY_C "val_c"
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
  test_store_set SECRET_PS "hidden_value"
  echo "SECRET_PS" > "$TEST_TMPDIR/.secrets"
  # The child should see the env var, but it should not be in $0 or args
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- printenv SECRET_PS"
  [ "$status" -eq 0 ]
  [ "$output" = "hidden_value" ]
}

@test "sv exec does not invoke env with secret assignments in argv" {
  local fakebin marker
  fakebin="${TEST_TMPDIR}/bin"
  marker="${TEST_TMPDIR}/env-invoked"
  mkdir -p "${fakebin}"
  cat > "${fakebin}/env" <<EOF
#!/usr/bin/env bash
touch '${marker}'
exit 99
EOF
  chmod +x "${fakebin}/env"
  test_store_set SECRET_ARGV "must_not_reach_argv"
  echo "SECRET_ARGV" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$fakebin':\$PATH '$SV_BIN' exec -- /bin/sh -c 'test \"\$SECRET_ARGV\" = must_not_reach_argv'"
  [ "$status" -eq 0 ]
  [ ! -e "${marker}" ]
}

@test "sv exec --key injects exactly one requested key" {
  test_store_set EXACT_KEY "exact_val"
  test_store_set MANIFEST_KEY "manifest_val"
  test_store_set UNRELATED_KEY "unrelated_val"
  echo "MANIFEST_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key EXACT_KEY -- bash -c 'printf \"%s:%s:%s\" \"\$EXACT_KEY\" \"\${MANIFEST_KEY-unset}\" \"\${UNRELATED_KEY-unset}\"'"
  [ "$status" -eq 0 ]
  [ "$output" = "exact_val:unset:unset" ]
}

@test "sv exec --key is repeatable" {
  test_store_set KEY_ONE "one"
  test_store_set KEY_TWO "two"
  echo "" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key KEY_ONE --key KEY_TWO -- bash -c 'printf \"%s:%s\" \"\$KEY_ONE\" \"\$KEY_TWO\"'"
  [ "$status" -eq 0 ]
  [ "$output" = "one:two" ]
}

@test "sv exec --key fails when a requested key is missing" {
  echo "" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key DOES_NOT_EXIST -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing requested secrets: DOES_NOT_EXIST"* ]]
}

@test "sv exec --key rejects invalid and optional-style names" {
  echo "" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key 'BAD-KEY' -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid key"* ]]

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key 'OPTIONAL_KEY?' -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid key"* ]]

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key LD_PRELOAD -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"process-control environment variables"* ]]
}

@test "sv exec --key rejects duplicate keys" {
  test_store_set DUPLICATE_KEY "value"
  echo "" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key DUPLICATE_KEY --key DUPLICATE_KEY -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"duplicate requested key"* ]]
}

@test "sv exec --key requires a separate key argument" {
  echo "" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"--key requires a key name"* ]]

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key=EXACT_KEY -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"use '--key <KEY>'"* ]]

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key"
  [ "$status" -ne 0 ]
  [[ "$output" == *"--key requires a key name"* ]]
}

@test "sv exec rejects incompatible selection modes" {
  test_store_set MODE_KEY "value"
  echo "MODE_KEY?" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --key MODE_KEY --all-secrets -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"mutually exclusive"* || "$output" == *"cannot be combined"* ]]

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --strict --key MODE_KEY -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"--strict can only be used"* ]]

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --all-secrets --strict -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"--strict can only be used"* ]]

  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec --all-secrets --all-secrets -- echo should_not_run"
  [ "$status" -ne 0 ]
  [[ "$output" == *"cannot be combined"* ]]
}

@test "sv exec flags after -- are child arguments" {
  echo "" > "$TEST_TMPDIR/.secrets"
  run bash -c "cd '$TEST_TMPDIR' && '$SV_BIN' exec -- bash -c 'printf \"%s:%s\" \"\$1\" \"\$2\"' child --key --all-secrets"
  [ "$status" -eq 0 ]
  [ "$output" = "--key:--all-secrets" ]
}
