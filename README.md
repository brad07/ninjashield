# NinjaShield

A local firewall and command gate for AI agent tools. NinjaShield sits between agent tools (Claude Code, Codex, etc.) and external APIs/LLM providers to inspect, classify, redact, approve/deny, and audit outbound requests and shell commands.

## What It Does

- **Command Gate** — Evaluates shell commands from AI agents against policy rules. Safe commands auto-approve, risky ones require human confirmation, dangerous ones get blocked.
- **LLM/API Firewall** — Intercepts outbound LLM and API requests to scan for secrets, PII, and sensitive data before they leave your machine.
- **Local LLM Risk Scoring** — Optional AI-based risk assessment using local models via Ollama or LM Studio.
- **Plugin System** — Extensible architecture for scanners, LLM providers, and integrations with hot-reload support.

## Quick Start

### Prerequisites

- Go 1.21+
- (Optional) [Ollama](https://ollama.ai) for local LLM risk scoring

### Build

```bash
make build
```

### Run

```bash
# Start the daemon with default settings (balanced policy)
./bin/ninjashieldd

# Use a specific policy pack
./bin/ninjashieldd --pack=conservative

# Enable local LLM risk scoring
./bin/ninjashieldd --llm=ollama --llm-model=gemma3

# Enable the plugin system
./bin/ninjashieldd --plugins
```

The daemon listens on `localhost:7575` by default.

### Test a Command

```bash
# Evaluate a command
curl -s http://localhost:7575/v1/commands/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"command": "ls -la", "cwd": "/tmp"}' | jq .

# Check health
curl http://localhost:7575/health
```

## Claude Code Integration

Add NinjaShield as a hook in `~/.claude/settings.json`:

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

When active, every Bash command Claude Code runs is evaluated against NinjaShield policy before execution.

## Policy Packs

| Pack | Description |
|------|-------------|
| `conservative` | Stricter rules, blocks more commands |
| `balanced` | Default — good security/usability balance |
| `developer-friendly` | Allows more, focuses on truly dangerous operations |

Project-level overrides can be placed in `.ninjashield/policy.yaml` in your project root.

## Configuration

Configuration lives at `~/.ninjashield/config.yaml`. Key settings:

```yaml
server:
  host: localhost
  port: 7575

policy:
  active_pack: balanced

scanners:
  secrets: true
  pii: true
  commands: true

llm:
  enabled: false
  provider: ollama
  endpoint: http://localhost:11434
  model: gemma3
  mode: fast  # fast or strict

plugins:
  hot_reload: true
  scanners:
    secrets:
      enabled: true
      priority: 100
    pii:
      enabled: true
      priority: 90
    commands:
      enabled: true
      priority: 95
  llm_providers:
    ollama:
      enabled: true
      endpoint: http://localhost:11434
      model: gemma3
```

## Plugin System

NinjaShield supports three plugin types:

- **Scanners** — Analyze content for secrets, PII, dangerous commands, etc.
- **LLM Providers** — Integrate local LLM backends (Ollama, LM Studio) for AI risk scoring.
- **Integrations** — Connect to external tools (Claude Code, OpenClaw).

Built-in plugins are in `plugins/`. External plugins can be loaded from `~/.ninjashield/plugins/`.

## Project Structure

```
cmd/
  ninjashield/     CLI tool
  ninjashieldd/    Daemon server
pkg/
  config/          Configuration loading
  llm/             LLM request evaluation engine
  localllm/        Local LLM provider abstraction
  plugin/          Plugin system (manager, registry, pipeline)
  policy/          Policy engine and rule packs
  proxy/           HTTP proxy
  redact/          Content redaction
  scanners/        Content scanners (secrets, PII, commands)
  server/          HTTP server and API
  storage/         Audit log storage
plugins/           Built-in plugins
integrations/
  claude-code/     Claude Code hook integration
  openclaw/        OpenClaw hook integration
```

## Development

```bash
make test           # Run tests
make test-coverage  # Tests with coverage report
make lint           # Run linter
make build-all      # Cross-platform builds (Linux, macOS, Windows)
```

## License

See [LICENSE](LICENSE) for details.
