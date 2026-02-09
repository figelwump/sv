#!/usr/bin/env bats
# validation.bats — input validation, error messages, CLI routing/aliases

load test_helper

# ─── Key validation ──────────────────────────────────────────────────────────

@test "rejects key with hyphens" {
  run bash -c "echo val | '$SV_BIN' set bad-key"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid key"* ]]
}

@test "rejects key starting with digit" {
  run bash -c "echo val | '$SV_BIN' set 9KEY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid key"* ]]
}

@test "accepts key starting with underscore" {
  run bash -c "echo val | '$SV_BIN' set _PRIVATE"
  [ "$status" -eq 0 ]
  result="$(test_kc_get _PRIVATE)"
  [ "$result" = "val" ]
}

@test "accepts uppercase key with underscores and digits" {
  run bash -c "echo val | '$SV_BIN' set UPPER_CASE_123"
  [ "$status" -eq 0 ]
  result="$(test_kc_get UPPER_CASE_123)"
  [ "$result" = "val" ]
}

@test "accepts lowercase key" {
  run bash -c "echo val | '$SV_BIN' set lower_case"
  [ "$status" -eq 0 ]
  result="$(test_kc_get lower_case)"
  [ "$result" = "val" ]
}

@test "rejects key with spaces" {
  run bash -c "echo val | '$SV_BIN' set 'HAS SPACE'"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid key"* ]]
}

@test "rejects key with dots" {
  run bash -c "echo val | '$SV_BIN' set 'my.key'"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid key"* ]]
}

# ─── Positional value rejection ──────────────────────────────────────────────

@test "sv set rejects positional value argument" {
  run "$SV_BIN" set MY_KEY some_value
  [ "$status" -ne 0 ]
  [[ "$output" == *"do not pass the value as an argument"* ]]
}

# ─── Empty value rejection ───────────────────────────────────────────────────

@test "sv set rejects empty value from stdin" {
  run bash -c "echo '' | '$SV_BIN' set MY_KEY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"no value provided"* ]]
}

# ─── Missing args / usage ───────────────────────────────────────────────────

@test "sv set with no key shows usage" {
  run "$SV_BIN" set
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}

@test "sv get with no key shows usage" {
  run "$SV_BIN" get
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}

@test "sv rm with no key shows usage" {
  run "$SV_BIN" rm
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}

@test "sv exec with no command shows usage" {
  run "$SV_BIN" exec
  [ "$status" -ne 0 ]
  [[ "$output" == *"usage"* ]]
}

# ─── Unknown command ─────────────────────────────────────────────────────────

@test "unknown command shows error" {
  run "$SV_BIN" frobnicate
  [ "$status" -ne 0 ]
  [[ "$output" == *"unknown command"* ]]
  [[ "$output" == *"frobnicate"* ]]
}

# ─── Version aliases ─────────────────────────────────────────────────────────

@test "sv version prints version" {
  run "$SV_BIN" version
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "sv --version prints version" {
  run "$SV_BIN" --version
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

@test "sv -v prints version" {
  run "$SV_BIN" -v
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

# ─── Help aliases ────────────────────────────────────────────────────────────

@test "sv help shows help text" {
  run "$SV_BIN" help
  [ "$status" -eq 0 ]
  [[ "$output" == *"simple secret vault"* ]]
}

@test "sv --help shows help text" {
  run "$SV_BIN" --help
  [ "$status" -eq 0 ]
  [[ "$output" == *"simple secret vault"* ]]
}

@test "sv -h shows help text" {
  run "$SV_BIN" -h
  [ "$status" -eq 0 ]
  [[ "$output" == *"simple secret vault"* ]]
}

# ─── rm/remove and ls/list aliases ───────────────────────────────────────────

@test "sv remove is alias for sv rm" {
  test_kc_set ALIAS_KEY "alias_val"
  run "$SV_BIN" remove ALIAS_KEY
  [ "$status" -eq 0 ]
  run test_kc_get ALIAS_KEY
  [ "$status" -ne 0 ]
}

@test "sv list is alias for sv ls" {
  test_kc_set LIST_KEY "list_val"
  run "$SV_BIN" list
  [ "$status" -eq 0 ]
  [[ "$output" == *"LIST_KEY"* ]]
}

# ─── Default (no args) shows help ───────────────────────────────────────────

@test "sv with no args shows help" {
  run "$SV_BIN"
  [ "$status" -eq 0 ]
  [[ "$output" == *"simple secret vault"* ]]
}
