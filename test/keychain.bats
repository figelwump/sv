#!/usr/bin/env bats
# keychain.bats — CRUD operations on secrets via sv set/get/rm/ls

load test_helper

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
