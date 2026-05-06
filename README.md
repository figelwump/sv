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

# Run any command with secrets injected
sv exec -- npm run dev
sv exec -- node test.js
sv exec -- pytest
```

## How it works

On macOS, secrets are stored in the Keychain under the service prefix `sv:`. The native `security` CLI does the heavy lifting.

On Linux, secrets are stored in `pass` under the `sv/` namespace inside your password store. `sv` expects `pass init <gpg-id>` to have already been run.

`sv exec -- <cmd>` resolves secrets and injects them as environment variables into the subprocess. The calling process (or agent) never sees the values.

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
```

- When present, `sv exec` only injects listed secrets and **fails if any are missing** from the active backend.
- When absent, all stored secrets are injected.
- The manifest is found by searching up from the current directory, so running from a subdirectory works.

## Agent usage

Agents prefix commands with `sv exec --` to run with secrets. They never see the actual values:

```bash
sv exec -- npm test
sv exec -- node scripts/call-api.js
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
Never ask for or hardcode secret values. The `sv` tool injects them automatically.
Do NOT use `sv get`, `printenv`, `env`, `security find-generic-password`, or
`pass show` to read secret values. These commands exist for human use only.
```

## Security

- **`sv set`** never accepts the value as a CLI argument — it prompts interactively or reads stdin. This keeps secrets out of shell history.
- **`sv get`** is gated behind a TTY check — it refuses to print values when stdout is piped or captured. This blocks agents (which capture command output) from reading secrets through `sv get`.
- **Linux `sv exec`** depends on `gpg-agent` state. If the agent is locked, non-interactive processes cannot satisfy the passphrase prompt.
- **`.secrets` manifests** declare requirements by name only and are safe to commit. They scope injection so projects only get the secrets they need.

These are practical barriers, not a hard sandbox. An agent with shell access could still extract secrets through other means. The real enforcement is agent instructions.

## Testing

Tests use [bats-core](https://github.com/bats-core/bats-core) and run against the real backend — no mocks, no fakes.

- macOS tests use an isolated `sv_test:` Keychain namespace.
- Linux tests use a temporary password store and temporary GPG home.

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
| `sv exec -- <cmd>` | Run command with secrets injected |
| `sv unlock <KEY>` | Unlock Linux GPG agent without printing a secret |
| `sv doctor` | Check backend setup and common failures |
| `sv update` | Update to latest version |
| `sv version` | Print version |
| `sv help` | Show help |
