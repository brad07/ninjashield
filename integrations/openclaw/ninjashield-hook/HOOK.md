---
name: ninjashield
description: "AI-powered command security scanning via NinjaShield"
homepage: https://github.com/brad07/ninjashield
metadata: {"openclaw":{"emoji":"🛡️","events":["exec:before"],"requires":{"bins":["curl","jq"]}}}
---

# NinjaShield Hook

AI-powered command security scanning for OpenClaw. Evaluates shell commands before execution using local LLM (Ollama) to detect:

- Data exfiltration attempts
- Reverse shells
- Credential theft
- System damage commands
- Privilege escalation

## What It Does

- Intercepts `exec:before` events
- Sends commands to NinjaShield daemon for evaluation
- Returns risk assessment with allow/deny/ask decision
- Integrates with OpenClaw's approval flow

## Requirements

- NinjaShield daemon running (`ninjashieldd`)
- curl and jq installed
- Optional: Ollama for AI-based scoring

## Configuration

Set environment variables:
- `NINJASHIELD_URL`: Daemon URL (default: `http://localhost:7575`)
- `NINJASHIELD_TIMEOUT`: Request timeout in seconds (default: `15`)

## Usage

1. Start NinjaShield daemon:
   ```bash
   ninjashieldd --llm=ollama --llm-model=gemma3:4b
   ```

2. Enable the hook:
   ```bash
   openclaw hooks enable ninjashield
   ```

3. Commands will be evaluated before execution
