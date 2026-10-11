# sv — simple secret vault

Local dev secret management for macOS and Linux. Stores secrets in the macOS Keychain or Linux password-store, then injects them into processes on demand.

No plaintext secret files, no database, no daemon. One script, one command prefix: `sv exec --`.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/figelwump/sv/main/install.sh | bash
```

- macOS requires the native `security` CLI.
- On Debian / Raspberry Pi OS, `install.sh` will try to install `pass`, `gpg`, and `pinentry-curses` automatically.
- On other Linux distros, install `pass`, `gpg`, and a pinentry program first, then run `sv doctor` after install.

Or clone and copy manually:

```bash
git clone https://github.com/figelwump/sv.git
cp sv/sv /usr/local/bin/sv
```

## Update

```bash
sv update
```

## Quick start

```bash
# Store secrets (always prompts — values never touch shell history)
sv set OPENAI_API_KEY
sv set ANTHROPIC_API_KEY

# Or pipe from another source
echo "sk-proj-..." | sv set OPENAI_API_KEY

# List stored secret names (never values)
sv ls

# Declare the project's dependencies (names only; safe to commit)
printf 'OPENAI_API_KEY\nANTHROPIC_API_KEY?\n' > .secrets

# Run with the nearest .secrets manifest
sv exec -- npm run dev
sv exec -- pytest

# Or inject one confidently known dependency, bypassing the manifest
sv exec --key ANTHROPIC_API_KEY -- node reviewer.mjs
```

## How it works

On macOS, secrets are stored in the Keychain under the service prefix `sv:`. The native `security` CLI does the heavy lifting.

On macOS, `sv doctor` checks Keychain metadata and, when at least one `sv:` item exists, reads and discards one existing item's password data. It also reads and discards every present manifest item's password data before reporting that item as available. If metadata is accessible but a value read is blocked, `sv doctor` fails. Retry from an interactive macOS session that can present a Keychain authorization prompt; if the read still fails, review the item's Access Control settings in Keychain Access.

On Linux, secrets are stored in `pass` under the `sv/` namespace inside your password store. `sv` expects `pass init <gpg-id>` to have already been run.

`sv exec -- <cmd>` resolves the nearest `.secrets` manifest and injects those secrets as environment variables into the subprocess. The calling process (or agent) never sees the values. Exact-key mode (`--key`) bypasses manifest discovery, while `--all-secrets` explicitly opts into broad vault access.

## Linux / Raspberry Pi setup

On Debian / Raspberry Pi OS, start with:

```bash
./install.sh
sv doctor
```

If `sv doctor` reports that no secret GPG key exists, create one and initialize `pass`:

```bash
gpg --full-generate-key
gpg --list-secret-keys --keyid-format=long
pass init <gpg-id>
sv doctor
```

Notes:

- `sv` uses `~/.password-store` by default, or `PASSWORD_STORE_DIR` if you already set it.
- `sv doctor` is the main troubleshooting command for Linux setup and session issues.
- On headless Linux or Raspberry Pi, `sv set`, `sv get`, and `sv exec` may require an already-unlocked `gpg-agent`.
- Linux agent usage is not fully fire-and-forget after a fresh boot. In practice, a human usually needs to unlock `gpg-agent` once in a real terminal session before agents can use `sv exec` non-interactively.
- To unlock without printing a value, run `sv unlock <KEY>` from an interactive terminal. Over SSH, use a TTY:

  ```bash
  ssh -t pi 'cd /home/figelwump/vishal/repos/heybox && sv unlock TEST_KEY'
  ```

  After that, non-interactive agent commands can retry `sv exec` until `gpg-agent` cache expires or the Pi reboots.
- If `sv` says the Linux password store is not initialized, initialize it with `pass init <gpg-id>` first.

## Project manifests

Create a `.secrets` file in your project root listing the secret names it needs:

```
# .secrets — commit this file, it contains no values
OPENAI_API_KEY
DATABASE_URL
ANTHROPIC_API_KEY?
```

- When present, `sv exec` only injects listed secrets and **fails if any required secrets are missing** from the active backend.
- Add `?` to mark a secret optional. Missing optional secrets are skipped; present optional secrets are injected.
- If a manifest has only optional entries and none are available, `sv exec` runs the command without requiring the backend to be initialized; `--strict` restores required-secret behavior.
- Use `sv exec --strict -- <cmd>` to treat optional secrets as required for one command.
- `sv doctor` reports required and optional manifest status separately when backend checks pass.
- When absent, ordinary `sv exec` fails before starting the child. Create a manifest, use repeatable `--key <KEY>` for confidently known dependencies, or explicitly request legacy broad behavior with `--all-secrets`.
- The manifest is found by searching up from the current directory, so running from a subdirectory works.
- An empty or comments-only manifest is valid and runs the child without injected secrets.

## Execution modes

`sv exec` has three mutually exclusive selection modes. The `--` separator before the child command is required.

```bash
# Normal project workflow: nearest .secrets manifest
sv exec -- npm test

# Exact dependencies: bypass the manifest and inject only these names
sv exec --key ANTHROPIC_API_KEY -- node reviewer.mjs
sv exec --key API_KEY --key DATABASE_URL -- ./integration-test.sh

# Explicit legacy behavior: ignore any manifest and inject the complete vault
sv exec --all-secrets -- legacy-command
```

`--strict` is manifest-only and treats optional `KEY?` entries as required. It cannot be combined with `--key` or `--all-secrets`. Duplicate `--key` names and invalid environment-variable names are rejected.

## 1Password sync (optional)

1Password can be the source of truth for your secrets, with the local Keychain or password store as the copy that `sv exec` reads. 1Password is optional: only `sv sync` and the fetch of a missing key call the 1Password CLI (`op`). Without `op`, every command works as before.

### Setup

1. Install the 1Password CLI (macOS: `brew install 1password-cli`). On a machine with the 1Password app, turn on **Settings > Developer > Integrate with 1Password CLI**.
2. Create a vault named `sv`.
3. Add one item per secret. The item title is the key name, such as `GH_TOKEN`, and the value goes in the item's `password` field. A **Password** item has this field.

### Commands

```bash
sv sync              # copy every item in the vault into the local store
sv sync GH_TOKEN     # copy one key, e.g. after you rotate it in 1Password
```

- `sv sync` never prints values. It reports each key it synced and each key it could not sync.
- If 1Password cannot supply a value (no such item, an empty value, or a value with more than one line), the stored value stays unchanged and `sv sync` exits nonzero.
- A title that is not a valid key name, such as `My Login`, is skipped with a warning.
- 1Password matches titles without regard to case. If two titles differ only in case, `sv sync` skips both and exits nonzero.

### Fetch of missing keys in `sv exec`

When `sv exec` finds a required key missing from the local store, it reads that key from 1Password once, stores it, and continues. Later runs read only the local store.

- Only keys that would otherwise make `sv exec` fail are fetched: required manifest entries, every entry under `--strict`, and `--key` names. Optional `KEY?` entries are never fetched, so a run never waits on 1Password for a key that is intentionally absent.
- A successful run never calls `op`, so `sv exec` is as fast as before.
- On a machine with the 1Password app, a fetch can show a 1Password authorization prompt. If nobody answers within `SV_OP_TIMEOUT_SECONDS`, the fetch fails and `sv exec` reports the key as missing, so an unattended agent does not hang.
- Set `SV_OP_FETCH=0` to turn off the fetch.

Rotation is not automatic. After you change a value in 1Password, run `sv sync KEY` on each machine that has the old value.

### Headless machines

A machine without the 1Password app, such as a build host reached over SSH, can use a 1Password service account. Give the account read-only access to the `sv` vault, then store its token in `sv`:

```bash
sv set OP_SERVICE_ACCOUNT_TOKEN
sv sync
```

`sv` passes the stored token only to `op`, through that process's environment. Commands run by `sv exec` do not receive it unless a manifest lists it. A token already set in the environment takes precedence. Use one service account per machine, so that you can revoke one machine's access without affecting the others.

### Settings

| Variable | Default | Effect |
|---|---|---|
| `SV_OP_VAULT` | `sv` | Vault name or ID to read from |
| `SV_OP_FIELD` | `password` | Field that holds each value |
| `SV_OP_FETCH` | `1` | `0` turns off the fetch in `sv exec` |
| `SV_OP_TIMEOUT_SECONDS` | `60` | How long `sv` waits for one `op` call before it fails |

`sv doctor` reports whether `op` is installed and which authentication it will use. It does not call `op`, so it never shows a 1Password prompt.

## Agent usage

Agents normally use manifest-scoped `sv exec` and do not guess transitive dependencies. They never see the actual values:

```bash
sv exec -- npm test
```

For a confidently known dependency, make the name visible without exposing its value:

```bash
sv exec --key ANTHROPIC_API_KEY -- node scripts/reviewer.mjs
```

On Linux, this assumes `gpg-agent` is already unlocked in the current session. If it is not, `sv exec` may fail in non-interactive SSH contexts before the target command starts. In that case, the agent should ask the human user to run the unlock step in an interactive SSH terminal:

```bash
ssh -t pi 'cd /home/figelwump/vishal/repos/heybox && sv unlock TEST_KEY'
```

Then the agent can retry:

```bash
ssh pi 'cd /home/figelwump/vishal/repos/heybox && sv exec -- .venv/bin/python scripts/list_spotify_devices.py'
```

Fully unattended Linux use requires an explicit security tradeoff, such as a no-passphrase dedicated GPG key or separate host-level unlock automation. That is not `sv`'s default.

Add to your project's `AGENTS.md`:

```markdown
## Secrets

Use `sv exec -- <command>` to run commands that need API keys or secrets.
Normal execution is scoped by the nearest committed `.secrets` manifest. Do not
guess transitive dependencies. When a dependency is confidently known, use
`sv exec --key <KEY> -- <command>`. Use `--all-secrets` only with explicit user
intent to expose the complete vault to the child process.
Never ask for or hardcode secret values. The `sv` tool injects them automatically.
Do NOT use `sv get`, `printenv`, `env`, `security find-generic-password`, or
`pass show` to read secret values. These commands exist for human use only.
```

## Security

- **`sv set`** never accepts the value as a CLI argument — it prompts interactively or reads stdin. This keeps secrets out of shell history.
- **`sv get`** is gated behind a TTY check — it refuses to print values when stdout is piped or captured. This blocks agents (which capture command output) from reading secrets through `sv get`.
- **Linux `sv exec`** depends on `gpg-agent` state. If the agent is locked, non-interactive processes cannot satisfy the passphrase prompt.
- **`.secrets` manifests** declare requirements by name only and are safe to commit. They scope injection so projects only get the secrets they need.
- **Exact-key execution** exposes selected names in argv for review while values remain in the child environment. `--key` accepts names, never values.
- **Process-control environment names are rejected.** Secret selection cannot replace loader, shell-startup, or executable-search variables such as `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, or `PATH`.
- **Broad execution is explicit.** `--all-secrets` is the only mode that injects the complete vault and ignores a discovered manifest.
- **Backend failures remain distinct from missing keys.** An inaccessible Keychain or password store fails before child execution instead of being reported as an absent credential or empty vault.
- **1Password reads stay narrow.** `sv sync` and the fetch of a missing key write values straight into the local store without printing them. A stored service-account token reaches only the `op` process.
- **Exit status `2` identifies backend access failures.** Missing requested keys and invalid usage remain ordinary nonzero failures; callers can distinguish an inaccessible vault without inspecting secret values.

These are practical barriers, not a hard sandbox. An agent with shell access could still extract secrets through other means. The real enforcement is agent instructions.

## Testing

Tests use [bats-core](https://github.com/bats-core/bats-core). Most backend tests use the real backend; focused error-path tests replace the backend command with a local fake.

- macOS tests use an isolated `sv_test:` Keychain namespace.
- Linux tests use a temporary password store and temporary GPG home.
- 1Password tests (`test/op.bats`) use a fake `op` CLI. Other test files set `SV_OP_FETCH=0`, so no test reaches a real 1Password account.

```bash
bats --version           # verify bats is installed
make test                # run all tests
make test-keychain       # macOS only
make test-pass           # Linux only
make test-purge          # purge macOS test secrets
```

## Commands

| Command | Description |
|---|---|
| `sv set <KEY>` | Store a secret (prompts or reads stdin) |
| `sv get <KEY>` | Print a secret value (TTY only) |
| `sv rm <KEY>` | Delete a secret |
| `sv ls` | List secret names |
| `sv exec [--strict] -- <cmd>` | Run with the nearest `.secrets` manifest |
| `sv exec --key <KEY> [--key <KEY>...] -- <cmd>` | Run with exactly the named required secrets |
| `sv exec --all-secrets -- <cmd>` | Explicitly run with every stored secret |
| `sv sync [KEY...]` | Copy secrets from 1Password into the local store |
| `sv unlock <KEY>` | Unlock Linux GPG agent without printing a secret |
| `sv doctor` | Check backend setup and common failures |
| `sv update` | Update to latest version |
| `sv version` | Print version |
| `sv help` | Show help |

## Upgrading to 0.3.0

Version 0.3.0 adds `sv sync` and the fetch of missing keys. Nothing changes on machines without `op`. On a machine with `op`, a `sv exec` that would fail on a missing required key now first tries to read that key from 1Password, which can show a 1Password prompt. Set `SV_OP_FETCH=0` to keep the earlier behavior.

## Migrating from 0.1.x

Version 0.2.0 removes the implicit all-vault fallback and requires `--` before the child command.

- Add a committed `.secrets` manifest for ordinary project commands.
- Replace known one-off dependencies with `--key <KEY>`.
- Replace intentional legacy all-vault execution with `--all-secrets`.
- Change `sv exec command` to `sv exec -- command`.
- Treat Keychain/password-store access errors as backend failures; do not assume reported credentials are absent without checking `sv doctor` in an authorized session.
