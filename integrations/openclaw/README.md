# NinjaShield OpenClaw Integration

AI-powered command security scanning for [OpenClaw](https://openclaw.ai/).

## Installation

### Option 1: Link the hook directory

```bash
openclaw hooks install -l /path/to/ninjashield/integrations/openclaw/ninjashield-hook
openclaw hooks enable ninjashield
```

### Option 2: Copy the hook

```bash
openclaw hooks install /path/to/ninjashield/integrations/openclaw/ninjashield-hook
openclaw hooks enable ninjashield
```

## Requirements

1. **NinjaShield daemon** must be running:
   ```bash
   # Without AI (static rules only)
   ninjashieldd

   # With AI scoring (recommended)
   ollama serve &
   ninjashieldd --llm=ollama --llm-model=gemma3:4b
   ```

2. **curl** and **jq** must be installed (for the hook handler)

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `NINJASHIELD_URL` | `http://localhost:7575` | NinjaShield daemon URL |
| `NINJASHIELD_TIMEOUT` | `15` | Request timeout in seconds |

## How It Works

1. OpenClaw fires `exec:before` event when a command is about to run
2. NinjaShield hook intercepts the event and calls the daemon
3. Daemon evaluates the command using static rules + AI (if enabled)
4. Hook returns:
   - **ALLOW**: Command proceeds normally
   - **DENY**: Command blocked with error message
   - **ASK**: Triggers OpenClaw's approval flow with risk details

## Integration with OpenClaw Approvals

When NinjaShield returns ASK, the hook integrates with OpenClaw's approval system:

- Approval prompts show the NinjaShield risk score and context
- You can approve via the macOS companion app
- Or forward to chat channels and use `/approve <id> allow-once`

## Fail-Closed Behavior

NinjaShield is configured to fail closed:

- If the daemon is not running → **DENY**
- If the AI times out → **DENY**
- If there's a network error → **DENY**

This ensures no dangerous commands slip through if NinjaShield is unavailable.

## Testing

Check if NinjaShield is running:
```bash
curl http://localhost:7575/health
```

Test command evaluation:
```bash
curl -X POST http://localhost:7575/v1/commands/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"command":"rm -rf /","cwd":"/tmp"}'
```

## Troubleshooting

### Hook not firing
- Verify hook is enabled: `openclaw hooks list`
- Check hook is eligible: `openclaw hooks info ninjashield`

### Commands being blocked unexpectedly
- Check daemon logs: `tail -f /tmp/ninja.log`
- Verify AI is available: Check for "AI scoring: true" in logs
- Reduce risk thresholds in policy if needed

### Timeouts
- Ensure Ollama model is loaded (first request is slow)
- Increase timeout: `NINJASHIELD_TIMEOUT=30`
