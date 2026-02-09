# sv — simple secret vault

Local dev secret management for macOS. Stores secrets in Keychain, injects them into processes on demand.

## Install

```bash
# Symlink to somewhere on your PATH
ln -sf "$(pwd)/tools/sv/sv" /usr/local/bin/sv
```

## Quick start

```bash
# Store secrets once
sv set OPENAI_API_KEY sk-proj-...
sv set ANTHROPIC_API_KEY sk-ant-...

# Run any command with secrets injected
sv exec -- npm run dev
sv exec -- node test.js
sv exec -- pytest

# List stored secrets (names only, never values)
sv ls

# Shell integration — add to .zshrc for auto-loading
eval "$(sv shell-hook)"
```

## How it works

Secrets are stored in the macOS Keychain under the service prefix `sv:`. No files, no databases, no daemon. The `security` CLI does the heavy lifting.

`sv exec -- <cmd>` resolves secrets and injects them as environment variables into the subprocess. The calling process (or agent) never sees the values.

## Project manifests

Create a `.secrets` file in your project root listing the secret names it needs:

```
# .secrets — commit this, no values here
OPENAI_API_KEY
DATABASE_URL
```

When `sv exec` or `sv env` runs in a directory with `.secrets`, only those secrets are injected. Without a manifest, all stored secrets are injected.

## Agent usage

Agents prefix commands with `sv exec --` to run with secrets. They never see values:

```bash
sv exec -- npm test
sv exec -- node scripts/call-api.js
```

Add to your `AGENTS.md`:

```markdown
## Secrets

Use `sv exec -- <command>` to run commands that need API keys or secrets.
Never ask for or hardcode secret values. The `sv` tool injects them automatically.
```

## Commands

| Command | Description |
|---|---|
| `sv set <KEY> [value]` | Store a secret (prompts if no value) |
| `sv get <KEY>` | Print a secret value |
| `sv rm <KEY>` | Delete a secret |
| `sv ls` | List secret names |
| `sv exec -- <cmd>` | Run command with secrets injected |
| `sv env` | Print export statements for `eval` |
| `sv shell-hook` | Print shell integration code |
| `sv help` | Show help |
