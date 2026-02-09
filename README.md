# sv — simple secret vault

Local dev secret management for macOS. Stores secrets in Keychain, injects them into processes on demand.

## Install

```bash
# Symlink to somewhere on your PATH
ln -sf "$(pwd)/sv" /usr/local/bin/sv
```

## Quick start

```bash
# Store secrets (always prompts — never pass values as arguments)
sv set OPENAI_API_KEY
sv set ANTHROPIC_API_KEY

# Or pipe from another source
echo "sk-proj-..." | sv set OPENAI_API_KEY

# List stored secrets (names only, never values)
sv ls

# Run any command with secrets injected
sv exec -- npm run dev
sv exec -- node test.js
sv exec -- pytest
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

When `sv exec` runs in a directory with `.secrets` (searched up from cwd), only those secrets are injected — and it **fails if any are missing** from the keychain. Without a manifest, all stored secrets are injected.

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
| `sv set <KEY>` | Store a secret (prompts or reads stdin) |
| `sv get <KEY>` | Print a secret value |
| `sv rm <KEY>` | Delete a secret |
| `sv ls` | List secret names |
| `sv exec -- <cmd>` | Run command with secrets injected |
| `sv help` | Show help |
