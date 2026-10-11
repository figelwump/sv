#!/usr/bin/env bats
# op.bats — optional 1Password sync (sv sync) and the fetch of missing keys in sv exec

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
  unset SV_OP_FETCH

  TEST_TMPDIR="$(mktemp -d)"
  FAKEBIN="${TEST_TMPDIR}/bin"
  export FAKE_OP_ROOT="${TEST_TMPDIR}/op"
  export FAKE_OP_LOG="${TEST_TMPDIR}/op-calls.log"
  mkdir -p "${FAKEBIN}" "${FAKE_OP_ROOT}"

  # Fake 1Password CLI. Field values live in $FAKE_OP_ROOT/<vault>/<item>/<field>
  # and item listings in $FAKE_OP_ROOT/<vault>.json. Each call is logged with
  # the service-account token it received.
  cat > "${FAKEBIN}/op" <<'EOF'
#!/usr/bin/env bash
printf "%s token=%s\n" "$*" "${OP_SERVICE_ACCOUNT_TOKEN:-}" >> "${FAKE_OP_LOG}"
if [[ "${FAKE_OP_DRAIN_STDIN:-0}" == "1" ]]; then
  cat > /dev/null
fi
if [[ "${FAKE_OP_HANG:-0}" == "1" ]]; then
  # Like an unanswered authorization prompt. exec keeps one process to kill.
  exec sleep 30
fi
if [[ "${FAKE_OP_HANG:-0}" == "ignore-term" ]]; then
  # The ignored disposition survives exec, so only KILL stops this sleep.
  trap '' TERM
  exec sleep 30
fi
case "$1 $2" in
  "read op://"*)
    ref="${2#op://}"
    file="${FAKE_OP_ROOT}/${ref}"
    if [[ ! -f "${file}" ]]; then
      printf "[ERROR] could not read secret '%s': no matching item\n" "$2" >&2
      exit 1
    fi
    cat "${file}"
    printf "\n"
    ;;
  "item list")
    vault="$4"
    if [[ ! -f "${FAKE_OP_ROOT}/${vault}.json" ]]; then
      printf "[ERROR] \"%s\" isn't a vault in this account\n" "${vault}" >&2
      exit 1
    fi
    cat "${FAKE_OP_ROOT}/${vault}.json"
    ;;
  *)
    printf "unexpected op call: %s\n" "$*" >&2
    exit 1
    ;;
esac
EOF
  chmod +x "${FAKEBIN}/op"
}

teardown() {
  test_store_purge
  rm -rf "$TEST_TMPDIR"
}

# op_item <vault> <item> <value> [field]
op_item() {
  local dir="${FAKE_OP_ROOT}/$1/$2"
  mkdir -p "${dir}"
  printf "%s" "$3" > "${dir}/${4:-password}"
}

# op_list <vault> <title>... — writes a listing shaped like `op item list --format json`.
# Each item carries a decoy escaped "title" in a string field.
op_list() {
  local vault="$1" title first=1
  shift
  {
    printf "[\n"
    for title in "$@"; do
      [[ "${first}" -eq 1 ]] || printf ",\n"
      first=0
      printf '  {\n    "id": "id-%s",\n    "title": "%s",\n    "version": 1,\n' "${RANDOM}" "${title}"
      printf '    "vault": {\n      "id": "vault-id",\n      "name": "%s"\n    },\n' "${vault}"
      printf '    "category": "PASSWORD",\n'
      printf '    "additional_information": "note \\"title\\": \\"DECOY_KEY\\""\n  }'
    done
    printf "\n]\n"
  } > "${FAKE_OP_ROOT}/${vault}.json"
}

op_call_count() {
  if [[ -f "${FAKE_OP_LOG}" ]]; then
    wc -l < "${FAKE_OP_LOG}" | tr -d ' '
  else
    printf "0\n"
  fi
}

# Run sv with the fake op first on PATH.
sv_with_op() {
  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' $*"
}

# The backend tools live in /usr/bin and /bin; a typical op install does not.
PATH_WITHOUT_OP="/usr/bin:/bin"

require_path_without_op() {
  if PATH="${PATH_WITHOUT_OP}" command -v op >/dev/null 2>&1; then
    skip "op is installed in ${PATH_WITHOUT_OP}"
  fi
}

# ─── sv sync ─────────────────────────────────────────────────────────────────

@test "sv sync KEY copies the 1Password value without printing it" {
  op_item sv SYNC_KEY "value_from_op"
  sv_with_op sync SYNC_KEY
  [ "$status" -eq 0 ]
  [[ "$output" == *"synced SYNC_KEY"* ]]
  [[ "$output" != *"value_from_op"* ]]
  [ "$(test_store_get SYNC_KEY)" = "value_from_op" ]
  grep -q "^read op://sv/SYNC_KEY/password " "$FAKE_OP_LOG"
}

@test "sv sync replaces a rotated value" {
  test_store_set ROTATED_KEY "old_value"
  op_item sv ROTATED_KEY "new_value"
  sv_with_op sync ROTATED_KEY
  [ "$status" -eq 0 ]
  [ "$(test_store_get ROTATED_KEY)" = "new_value" ]
}

@test "sv sync honors SV_OP_VAULT and SV_OP_FIELD" {
  op_item Dev CUSTOM_KEY "custom_value" credential
  sv_with_op "sync CUSTOM_KEY"
  [ "$status" -ne 0 ]

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH SV_OP_VAULT=Dev SV_OP_FIELD=credential '$SV_BIN' sync CUSTOM_KEY"
  [ "$status" -eq 0 ]
  [ "$(test_store_get CUSTOM_KEY)" = "custom_value" ]
}

@test "sv sync with no keys copies every item and skips invalid titles" {
  op_list sv VAULT_A VAULT_B "My Login"
  op_item sv VAULT_A "value_a"
  op_item sv VAULT_B "value_b"
  sv_with_op sync
  [ "$status" -eq 0 ]
  [ "$(test_store_get VAULT_A)" = "value_a" ]
  [ "$(test_store_get VAULT_B)" = "value_b" ]
  [[ "$output" == *"skipping 1Password item 'My Login'"* ]]
  [[ "$output" != *"DECOY_KEY"* ]]
  ! grep -q "DECOY_KEY" "$FAKE_OP_LOG"
}

@test "sv sync skips titles that differ only in case and syncs the rest" {
  op_list sv DUP_KEY dup_key UNIQUE_KEY
  op_item sv DUP_KEY "dup_value"
  op_item sv UNIQUE_KEY "unique_value"
  sv_with_op sync
  [ "$status" -ne 0 ]
  [[ "$output" == *"skipping DUP_KEY: more than one item"* ]]
  [[ "$output" == *"skipping dup_key: more than one item"* ]]
  [ "$(test_store_get UNIQUE_KEY)" = "unique_value" ]
  [ -z "$(test_store_get DUP_KEY || true)" ]
}

@test "sv sync reports a vault that cannot be listed" {
  sv_with_op sync
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not list 1Password vault 'sv'"* ]]
  [[ "$output" == *"isn't a vault"* ]]
}

@test "sv sync keeps the stored value when 1Password cannot supply one" {
  test_store_set KEPT_MISSING "old_missing"
  test_store_set KEPT_EMPTY "old_empty"
  test_store_set KEPT_MULTI "old_multi"
  op_item sv KEPT_EMPTY ""
  op_item sv KEPT_MULTI $'line one\nline two'
  sv_with_op sync KEPT_MISSING KEPT_EMPTY KEPT_MULTI
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not read KEPT_MISSING"*"no matching item"* ]]
  [[ "$output" == *"empty value for KEPT_EMPTY"* ]]
  [[ "$output" == *"KEPT_MULTI"*"more than one line"* ]]
  [[ "$output" == *"3 key(s) did not sync"* ]]
  [[ "$output" != *"line one"* ]]
  [ "$(test_store_get KEPT_MISSING)" = "old_missing" ]
  [ "$(test_store_get KEPT_EMPTY)" = "old_empty" ]
  [ "$(test_store_get KEPT_MULTI)" = "old_multi" ]
}

@test "sv sync rejects invalid and duplicate key names before calling op" {
  sv_with_op sync "BAD-KEY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"invalid key"* ]]

  sv_with_op sync SAME_KEY SAME_KEY
  [ "$status" -ne 0 ]
  [[ "$output" == *"duplicate key: SAME_KEY"* ]]

  [ "$(op_call_count)" -eq 0 ]
}

@test "sv sync fails clearly without the op CLI" {
  require_path_without_op
  run env PATH="$PATH_WITHOUT_OP" "$SV_BIN" sync SOME_KEY
  [ "$status" -ne 0 ]
  [[ "$output" == *"needs the 1Password CLI"* ]]
}

@test "sv sync passes a stored service-account token to op, and an env token wins" {
  test_store_set OP_SERVICE_ACCOUNT_TOKEN "token_from_store"
  op_item sv TOKEN_KEY "token_value"
  sv_with_op sync TOKEN_KEY
  [ "$status" -eq 0 ]
  grep -q "token=token_from_store$" "$FAKE_OP_LOG"

  : > "$FAKE_OP_LOG"
  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH OP_SERVICE_ACCOUNT_TOKEN=token_from_env '$SV_BIN' sync TOKEN_KEY"
  [ "$status" -eq 0 ]
  grep -q "token=token_from_env$" "$FAKE_OP_LOG"
  ! grep -q "token_from_store" "$FAKE_OP_LOG"
}

# ─── sv exec fetch of missing keys ───────────────────────────────────────────

@test "sv exec fetches a missing required key once, then reads the store" {
  op_item sv FETCH_KEY "fetched_value"
  echo "FETCH_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- printenv FETCH_KEY 2>/dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "fetched_value" ]
  [ "$(test_store_get FETCH_KEY)" = "fetched_value" ]
  [ "$(op_call_count)" -eq 1 ]

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- printenv FETCH_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "fetched_value" ]
  [ "$(op_call_count)" -eq 1 ]
}

@test "sv exec reports the fetch on stderr" {
  op_item sv NOTICE_KEY "notice_value"
  echo "NOTICE_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- true"
  [ "$status" -eq 0 ]
  [[ "$output" == *"NOTICE_KEY is missing locally; reading it from 1Password"* ]]
  [[ "$output" == *"stored NOTICE_KEY from 1Password"* ]]
  [[ "$output" != *"notice_value"* ]]
}

@test "sv exec does not call op when required keys are present" {
  test_store_set PRESENT_KEY "present_value"
  op_item sv PRESENT_KEY "other_value"
  echo "PRESENT_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- printenv PRESENT_KEY"
  [ "$status" -eq 0 ]
  [ "$output" = "present_value" ]
  [ "$(op_call_count)" -eq 0 ]
}

@test "sv exec never fetches missing optional keys" {
  op_item sv OPTIONAL_KEY "optional_value"
  echo "OPTIONAL_KEY?" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- bash -c 'printf %s \"\${OPTIONAL_KEY-unset}\"'"
  [ "$status" -eq 0 ]
  [ "$output" = "unset" ]
  [ "$(op_call_count)" -eq 0 ]
}

@test "sv exec --strict fetches optional keys it treats as required" {
  op_item sv STRICT_KEY "strict_value"
  echo "STRICT_KEY?" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec --strict -- printenv STRICT_KEY 2>/dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "strict_value" ]
}

@test "sv exec --key fetches a missing requested key" {
  op_item sv EXPLICIT_KEY "explicit_value"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec --key EXPLICIT_KEY -- printenv EXPLICIT_KEY 2>/dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "explicit_value" ]
  [ "$(test_store_get EXPLICIT_KEY)" = "explicit_value" ]
}

@test "sv exec fails as before when 1Password has no value" {
  local marker="$TEST_TMPDIR/child-ran"
  echo "ABSENT_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- touch '$marker'"
  [ "$status" -ne 0 ]
  [[ "$output" == *"could not read ABSENT_KEY from 1Password"* ]]
  [[ "$output" == *"missing required secrets"*"ABSENT_KEY"* ]]
  [ ! -e "$marker" ]

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec --key ABSENT_KEY -- touch '$marker'"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing requested secrets: ABSENT_KEY"* ]]
  [ ! -e "$marker" ]
}

@test "sv exec fetches only the missing keys and injects all of them" {
  test_store_set HAVE_KEY "have_value"
  op_item sv NEED_KEY "need_value"
  printf "HAVE_KEY\nNEED_KEY\n" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- bash -c 'printf %s:%s \"\$HAVE_KEY\" \"\$NEED_KEY\"' 2>/dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "have_value:need_value" ]
  [ "$(op_call_count)" -eq 1 ]
  grep -q "^read op://sv/NEED_KEY/password " "$FAKE_OP_LOG"
}

@test "SV_OP_FETCH=0 turns off the fetch in sv exec" {
  op_item sv OFF_KEY "off_value"
  echo "OFF_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH SV_OP_FETCH=0 '$SV_BIN' exec -- true"
  [ "$status" -ne 0 ]
  [[ "$output" == *"missing required secrets"*"OFF_KEY"* ]]
  [ "$(op_call_count)" -eq 0 ]
}

@test "sv exec without the op CLI reports missing keys exactly as before" {
  require_path_without_op
  echo "NO_OP_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$PATH_WITHOUT_OP' '$SV_BIN' exec -- true"
  [ "$status" -ne 0 ]
  [ "$output" = "sv: missing required secrets (listed in $TEST_TMPDIR/.secrets): NO_OP_KEY" ]
}

@test "sv exec keeps piped stdin for the child after a fetch" {
  op_item sv STDIN_KEY "stdin_value"
  echo "STDIN_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && printf 'piped input' | PATH='$FAKEBIN':\$PATH FAKE_OP_DRAIN_STDIN=1 '$SV_BIN' exec -- cat 2>/dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "piped input" ]
}

@test "sv exec passes a stored service-account token to op but not to the child" {
  test_store_set OP_SERVICE_ACCOUNT_TOKEN "token_from_store"
  op_item sv CHILD_KEY "child_value"
  echo "CHILD_KEY" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- bash -c 'printf %s:%s \"\$CHILD_KEY\" \"\${OP_SERVICE_ACCOUNT_TOKEN-unset}\"' 2>/dev/null"
  [ "$status" -eq 0 ]
  [ "$output" = "child_value:unset" ]
  grep -q "token=token_from_store$" "$FAKE_OP_LOG"
}

@test "sv exec stops waiting for op after SV_OP_TIMEOUT_SECONDS" {
  local marker="$TEST_TMPDIR/child-ran" started elapsed
  echo "SLOW_KEY" > "$TEST_TMPDIR/.secrets"

  started=$SECONDS
  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH FAKE_OP_HANG=1 SV_OP_TIMEOUT_SECONDS=1 '$SV_BIN' exec -- touch '$marker'"
  elapsed=$((SECONDS - started))
  [ "$status" -ne 0 ]
  [ "$elapsed" -lt 10 ]
  [[ "$output" == *"op did not respond within 1 seconds"* ]]
  [[ "$output" == *"missing required secrets"*"SLOW_KEY"* ]]
  [ ! -e "$marker" ]
}

@test "sv sync stops waiting for op and keeps the stored value" {
  local started elapsed
  test_store_set SLOW_SYNC_KEY "old_slow"

  started=$SECONDS
  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH FAKE_OP_HANG=1 SV_OP_TIMEOUT_SECONDS=1 '$SV_BIN' sync SLOW_SYNC_KEY"
  elapsed=$((SECONDS - started))
  [ "$status" -ne 0 ]
  [ "$elapsed" -lt 10 ]
  [[ "$output" == *"op did not respond within 1 seconds"* ]]
  [ "$(test_store_get SLOW_SYNC_KEY)" = "old_slow" ]

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH SV_OP_TIMEOUT_SECONDS=soon '$SV_BIN' sync SLOW_SYNC_KEY"
  [ "$status" -ne 0 ]
  [[ "$output" == *"SV_OP_TIMEOUT_SECONDS must be a whole number"* ]]
}

@test "sv exec stops an op that ignores TERM" {
  local started elapsed
  echo "STUBBORN_KEY" > "$TEST_TMPDIR/.secrets"

  started=$SECONDS
  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH FAKE_OP_HANG=ignore-term SV_OP_TIMEOUT_SECONDS=1 '$SV_BIN' exec -- true"
  elapsed=$((SECONDS - started))
  [ "$status" -ne 0 ]
  [ "$elapsed" -lt 10 ]
  [[ "$output" == *"op did not respond within 1 seconds"* ]]
}

@test "sv exec waits for op once, not once per missing key" {
  local started elapsed
  printf "SLOW_ONE\nSLOW_TWO\nSLOW_THREE\n" > "$TEST_TMPDIR/.secrets"

  started=$SECONDS
  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH FAKE_OP_HANG=1 SV_OP_TIMEOUT_SECONDS=2 '$SV_BIN' exec -- true"
  elapsed=$((SECONDS - started))
  [ "$status" -ne 0 ]
  [ "$(op_call_count)" -eq 1 ]
  [ "$elapsed" -lt 8 ]
  [[ "$output" == *"not reading the remaining missing keys"* ]]
  [[ "$output" == *"missing required secrets"*"SLOW_ONE SLOW_TWO SLOW_THREE"* ]]
}

@test "sv sync stops after a timeout and counts the skipped keys" {
  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH FAKE_OP_HANG=1 SV_OP_TIMEOUT_SECONDS=1 '$SV_BIN' sync FIRST_KEY SECOND_KEY THIRD_KEY"
  [ "$status" -ne 0 ]
  [ "$(op_call_count)" -eq 1 ]
  [[ "$output" == *"skipping the 2 remaining key(s)"* ]]
  [[ "$output" == *"3 key(s) did not sync"* ]]
}

@test "sv sync ignores invalid titles when it looks for duplicates" {
  op_list sv "FOO BAR" "FOO BAR" FOO "*" "*"
  op_item sv FOO "foo_value"
  touch "$TEST_TMPDIR/FOO"
  sv_with_op sync
  [ "$status" -eq 0 ]
  [ "$(test_store_get FOO)" = "foo_value" ]
  [[ "$output" == *"synced FOO"* ]]
  [[ "$output" != *"more than one item"* ]]
}

@test "sv exec exits 2 when a stored service-account token cannot be read" {
  local real_cmd
  test_store_set OP_SERVICE_ACCOUNT_TOKEN "token_from_store"
  op_item sv BLOCKED_KEY "blocked_value"
  echo "BLOCKED_KEY" > "$TEST_TMPDIR/.secrets"

  # Make only the token's value read fail the way an inaccessible backend does.
  case "$(test_backend)" in
    keychain)
      real_cmd="$(command -v security)"
      cat > "${FAKEBIN}/security" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "find-generic-password" && " \$* " == *" ${SV_SERVICE_PREFIX}OP_SERVICE_ACCOUNT_TOKEN -w "* ]]; then
  echo "security: SecKeychainSearchCopyNext: User interaction is not allowed." >&2
  exit 36
fi
exec "${real_cmd}" "\$@"
EOF
      chmod +x "${FAKEBIN}/security"
      ;;
    pass)
      real_cmd="$(command -v pass)"
      cat > "${FAKEBIN}/pass" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "show" && "\$2" == "sv/OP_SERVICE_ACCOUNT_TOKEN" ]]; then
  echo "gpg: decryption failed: No secret key" >&2
  exit 2
fi
exec "${real_cmd}" "\$@"
EOF
      chmod +x "${FAKEBIN}/pass"
      ;;
  esac

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec -- true"
  [ "$status" -eq 2 ]
  [ "$(op_call_count)" -eq 0 ]

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' exec --key BLOCKED_KEY -- true"
  [ "$status" -eq 2 ]
  [ "$(op_call_count)" -eq 0 ]
}

@test "sv doctor reports a stored token even when a manifest key is missing" {
  test_store_set OP_SERVICE_ACCOUNT_TOKEN "token_from_store"
  echo "MISSING_FOR_DOCTOR" > "$TEST_TMPDIR/.secrets"

  run bash -c "cd '$TEST_TMPDIR' && PATH='$FAKEBIN':\$PATH '$SV_BIN' doctor"
  [ "$status" -ne 0 ]
  [[ "$output" == *"required secrets missing: MISSING_FOR_DOCTOR"* ]]
  [[ "$output" == *"service-account token stored in sv as OP_SERVICE_ACCOUNT_TOKEN"* ]]
  [ "$(op_call_count)" -eq 0 ]
}
