#!/usr/bin/env bash
#
# Copy existing sv secrets into the 1Password vault that `sv sync` reads, then
# confirm that 1Password holds the same value for each key.
#
# Usage: scripts/migrate-to-1password.sh [--skip KEY]...
#
# Each key becomes a Password item titled with the key name. Items already in
# the vault are left unchanged, so the script is safe to run again.
# OP_SERVICE_ACCOUNT_TOKEN is always skipped. Honors SV_OP_VAULT and SV_OP_FIELD.
#
# Values never appear in command arguments or output. `sv exec` passes each
# value to a child shell as an environment variable, that shell's printf
# builtin pipes it to `op item create -`, and the check compares values in
# memory.

set -euo pipefail

usage() {
  printf "usage: %s [--skip KEY]...\n" "$0" >&2
  exit 2
}

vault="${SV_OP_VAULT:-sv}"
field="${SV_OP_FIELD:-password}"
skip=" OP_SERVICE_ACCOUNT_TOKEN "

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip)
      [[ $# -ge 2 ]] || usage
      skip+="$2 "
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done

command -v op >/dev/null 2>&1 || { echo "error: the 1Password CLI (op) is not installed" >&2; exit 1; }
command -v sv >/dev/null 2>&1 || { echo "error: sv is not on PATH" >&2; exit 1; }

# Only read local values; never fetch a key from 1Password into sv.
export SV_OP_FETCH=0

if ! listing="$(op item list --vault "${vault}" --format json)"; then
  echo "error: could not list vault '${vault}'. Create it with: op vault create ${vault}" >&2
  exit 1
fi
titles="$(printf "%s\n" "${listing}" | grep -o '"title": *"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/')" || true

keys="$(sv ls)"
failed=0
checked=()

# 1Password matches titles without regard to case, as `sv sync` does.
in_vault() {
  printf "%s\n" "${titles}" | grep -qixF -- "$1"
}

for key in ${keys}; do
  if [[ "${skip}" == *" ${key} "* ]]; then
    echo "skip     ${key}"
    continue
  fi
  checked+=("${key}")

  if in_vault "${key}"; then
    echo "exists   ${key} (left unchanged)"
  elif sv exec --key "${key}" -- bash -c '
      value="${!1}"
      value="${value//\\/\\\\}"
      value="${value//\"/\\\"}"
      if [[ "$3" == "password" ]]; then
        item_field="{\"id\":\"password\",\"purpose\":\"PASSWORD\",\"type\":\"CONCEALED\",\"label\":\"password\",\"value\":\"${value}\"}"
      else
        item_field="{\"type\":\"CONCEALED\",\"label\":\"$3\",\"value\":\"${value}\"}"
      fi
      printf "{\"title\":\"%s\",\"category\":\"PASSWORD\",\"fields\":[%s]}" "$1" "${item_field}" \
        | op item create --vault "$2" - >/dev/null' _ "${key}" "${vault}" "${field}"; then
    echo "copied   ${key}"
  else
    echo "FAILED   ${key} (could not create the item)"
    failed=1
  fi
done

echo
echo "Checking values in 1Password:"
for key in "${checked[@]:-}"; do
  [[ -n "${key}" ]] || continue
  status=0
  sv exec --key "${key}" -- bash -c '
      vault_value="$(op read "op://$2/$1/$3")" || exit 4
      [[ "${vault_value}" == "${!1}" ]] || exit 3' _ "${key}" "${vault}" "${field}" || status=$?
  case "${status}" in
    0) echo "match    ${key}" ;;
    3) echo "DIFFERS  ${key} (sv sync would replace the local value with the 1Password value)"; failed=1 ;;
    *) echo "FAILED   ${key} (could not read it back from 1Password)"; failed=1 ;;
  esac
done

exit "${failed}"
