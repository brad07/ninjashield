# NinjaShield Claude Code Plugin

A Claude Code plugin that provides security decision control by evaluating Bash commands against NinjaShield policies before execution.

## Plugin Structure

```
ninjashield/
├── .claude-plugin/
│   └── plugin.json      # Plugin manifest
├── hooks/
│   └── hooks.json       # PreToolUse hook configuration
├── hook.sh              # Standalone hook script (alternative)
└── README.md
```

## Installation

### Option 1: Install as Plugin (Recommended)

1. **Start the NinjaShield daemon:**
   ```bash
   ninjashieldd
   ```

2. **Install the plugin:**
   ```bash
   claude --plugin-dir /path/to/ninjashield/integrations/claude-code
   ```

   Or add to a plugin marketplace and install via `/plugin install`.

### Option 2: Standalone Hook

If you prefer not to use the plugin system, add directly to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/ninjashield/integrations/claude-code/hook.sh"
          }
        ]
      }
    ]
  }
}
```

## Prerequisites

- **NinjaShield daemon** running on localhost:7575
- **jq** - JSON processor
- **curl** - HTTP client

```bash
# macOS
brew install jq curl

# Ubuntu
sudo apt install jq curl
```

## How It Works

1. Claude Code intercepts Bash tool calls via the PreToolUse hook
2. The hook sends the command to NinjaShield at `localhost:7575/v1/commands/evaluate`
3. NinjaShield evaluates against the active policy pack
4. Based on the decision:
   - **ALLOW** → Command executes immediately
   - **DENY** → Command is blocked
   - **ASK** → User is prompted for confirmation

## Configuration

### NinjaShield Daemon

Start with default settings:
```bash
ninjashieldd
```

With a specific policy pack:
```bash
ninjashieldd --pack=conservative
```

With Ollama AI risk scoring:
```bash
ninjashieldd --ollama --ollama-model=gemma3
```

### Policy Packs

| Pack | Description |
|------|-------------|
| `conservative` | Stricter rules, blocks more commands |
| `balanced` | Default, good security/usability balance |
| `developer-friendly` | Allows more, focuses on truly dangerous ops |

## Examples

### Allowed Command
```
> ls -la
[NinjaShield: ALLOW]
```

### Blocked Command
```
> rm -rf /
[NinjaShield: DENY - destructive command affecting root filesystem]
```

### Requires Confirmation
```
> cat ~/.ssh/id_rsa
[NinjaShield: ASK - command accesses SSH private keys]
Allow? (y/n)
```

## Troubleshooting

### Plugin not loading
```bash
# Verify plugin structure
ls -la /path/to/plugin/.claude-plugin/

# Test with verbose output
claude --plugin-dir /path/to/plugin
```

### Daemon not responding
```bash
# Check health
curl http://localhost:7575/health

# Start daemon
ninjashieldd
```

### Test hook manually
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/tmp"}' | ./hook.sh
```

## Uninstall

Remove the plugin directory from your Claude Code configuration, or if using standalone hooks, remove the NinjaShield entry from `~/.claude/settings.json`.
