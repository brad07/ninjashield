# NinjaShield — Product Requirements Document (PRD)

**Product name:** NinjaShield  
**Category:** Local LLM/API Firewall + Command Approval Gate  
**Platforms:** macOS, Windows, Linux  
**Primary users:** Developers building/using agent tools (e.g., Clawdbot), Security/IT admins, Teams adopting Claude Code / Codex  
**Document owner:** (you)  
**Status:** Draft v1

---

## 1. Summary

NinjaShield is a **local firewall/proxy** that sits between agent tools and external APIs/LLM providers to **inspect, classify, redact, approve/deny, and audit** outbound requests. It also includes a **Command Gate** that integrates via **hook support** with **Claude Code** and **Codex** to **auto-approve safe commands** and **require human approval** for risky actions.

NinjaShield can optionally run a **local risk assessment** per request/command using a **local LLM (Ollama)** before forwarding.

---

## 2. Problem Statement

Agent tooling (LLM copilots, autonomous agents, browser/CLI automation) can unintentionally:
- Exfiltrate **PII**, **credentials**, **source code**, legal docs, or customer data
- Execute **dangerous commands** (destructive file operations, privilege escalation, remote script execution)
- Call unapproved endpoints/models without governance
- Create inconsistent security posture across macOS/Windows/Linux and across multiple agent tools

Organizations and individuals need a **single local control point** to:
- Intercept outbound LLM/API calls
- Enforce policy (allow/deny/redact/require approval)
- Gate tool execution (shell commands, file operations) with safe auto-approvals
- Provide reliable audit logs for compliance and incident response

---

## 3. Goals and Non-goals

### 3.1 Goals
1. **Universal control point (best effort):** Capture and govern LLM/API calls from local apps and agent frameworks.
2. **Policy enforcement:** Allow/deny/rate-limit and redact/transform content to meet security rules.
3. **Command approval:** Auto-approve safe commands and require human approval for risky commands in Claude Code and Codex.
4. **Explainable auditing:** Structured logs with reason codes, replayable decisions, export to SIEM.
5. **Local risk assessment:** Optional Ollama-based scoring/classification for nuanced risk detection.
6. **Cross-platform packaging:** Simple install and updates on macOS/Windows/Linux.

### 3.2 Non-goals (v1)
- Defending against a fully malicious local admin user on the same machine.
- Guaranteed deep inspection for all apps without integration (TLS pinning will limit proxy visibility).
- LLM-only DLP (deterministic scanners remain the source of truth for hard-block cases).
- Full MDM / enterprise device management in v1 (supported as future tier).

---

## 4. User Personas

1. **Individual Developer (Consumer):** Wants “it just works” protection while coding with Claude/Codex.
2. **Agent Builder (Pro/dev):** Wants SDK + local gateway to reliably control all agent calls.
3. **Security/Compliance Lead (Business):** Needs policy packs, approval workflows, audit exports.
4. **IT Admin (Business):** Needs cross-platform deployment, updates, and consistent configuration.

---

## 5. Product Scope

NinjaShield has two primary surfaces:

1. **NinjaShield Proxy (LLM/API Firewall)**
   - Intercepts outbound LLM/API requests
   - Scans content, applies policy, forwards to upstream provider, logs decisions

2. **NinjaShield Gate (Command Approval via Hooks)**
   - Integrates with Claude Code and Codex via their hook/rules systems
   - Evaluates proposed commands, auto-allows safe, prompts for approval on risky, blocks unsafe

---

## 6. Proxy Architecture: Transparent Proxy vs Integration

### 6.1 Option A — Transparent / System Proxy Mode
**How it works:** Apps route traffic via OS proxy settings to NinjaShield.  
**Pros:** Broad coverage without code changes.  
**Cons:** HTTPS inspection requires TLS MITM (local root CA). Many clients use TLS pinning → opaque payloads.

**Outcome:** Good baseline governance, not guaranteed visibility.

### 6.2 Option B — Integrated Mode (SDK / Local Gateway)
**How it works:** Tools call `http://localhost` gateway or use SDK (OpenAI-compatible facade).  
**Pros:** Reliable inspection, rich metadata, no MITM required.  
**Cons:** Requires adoption per tool/vendor.

### 6.3 Recommendation
Ship **both modes**:
- Proxy mode for breadth
- SDK/gateway mode for high assurance

Include **auto-detection** and UX messaging:
- “Limited visibility detected (TLS pinning). For full protection, enable SDK mode.”

---

## 7. Core Use Cases

### 7.1 LLM/API Firewall
- Block prompts containing secrets (API keys, private keys, tokens).
- Redact PII before sending to external LLMs.
- Enforce provider/model allowlists (e.g., only approved models/endpoints).
- Require approval for file uploads, embeddings of sensitive docs, or code exfil.
- Provide structured audit logs and SIEM export.

### 7.2 Command Gate
- Auto-approve safe read-only commands.
- Require human approval for install/network/destructive/privileged commands.
- Block clearly dangerous patterns (remote execution pipelines, destructive wipes).
- Optionally rewrite commands into safer variants (dry-run-first, scoped paths).

---

## 8. Functional Requirements

### 8.1 Traffic Capture & Normalization (Proxy)
**FR-1:** Detect and classify target endpoints/providers (OpenAI, Anthropic, Google, Azure OpenAI, etc.).  
**FR-2:** Normalize requests into a canonical event:
- provider, model, endpoint, request_type (chat/completions/embeddings/files/tools)
- messages/system/tools, attachments metadata
- caller attribution (best effort), timestamp, machine_id, user

**FR-3:** Support streaming responses (SSE/chunked) without breaking clients.  
**FR-4:** Support policy actions: allow/deny/redact/transform/require-approval/log-only.

### 8.2 Policy Engine (Deterministic + LLM-assisted)
**FR-5:** Deterministic scanners run first:
- secrets detection (key formats, entropy checks)
- PII detection (emails, phones, addresses; configurable)
- source code detection (heuristics + file type hints)
- “regulated content” tags (configurable)

**FR-6:** Policy rules support:
- destination/provider/model allowlists & denylists
- content class triggers (PII, secrets, code, legal, financial)
- attachment rules
- rate limiting & quotas
- per-repo or per-directory scopes

**FR-7:** Policy actions:
- **BLOCK** with reason
- **REDACT** specific fields or patterns
- **TRANSFORM** (remove stack traces, trim large payloads, drop attachments)
- **REQUIRE_APPROVAL** (local prompt, time-bound allow)
- **LOG_ONLY** (monitor mode)

### 8.3 Local Risk Assessment via Ollama
**FR-8:** Optional Ollama scoring step after deterministic scan:
- Input: minimized structured summary (avoid raw secrets if already detected)
- Output: risk_score 0–100, risk_categories, recommended_action, short explanation
- Use: advisory scoring + decision support (not sole authority for hard blocks)

**FR-9:** Configurable modes:
- Off
- Fast (low latency model / small context)
- Strict (more thorough, higher latency)

### 8.4 Command Gate (Hook Support)

#### 8.4.1 Claude Code Hooking
**FR-10:** Provide a `PreToolUse` hook integration for Bash (and optionally file tools).  
**FR-11:** On each proposed command:
- compute risk
- return decision: allow / ask / deny
- optionally return `updatedInput` to rewrite command
- add `additionalContext` to guide the agent

**FR-12:** Support “hard block” semantics for dangerous commands (deny plus a forced blocking return path).

#### 8.4.2 Codex Hooking (Rules + Approval Policy)
**FR-13:** Generate Codex rule files from NinjaShield policy to produce allow/prompt/forbidden decisions.  
**FR-14:** Provide recommended Codex config defaults (approval_policy + sandbox posture).  
**FR-15:** Provide a local command evaluator to test policies against a command string.

### 8.5 Approval UX
**FR-16:** When approval required, present a clear prompt (GUI and/or TUI):
- command/request summary
- risk score + reasons
- destination/provider/model (for LLM calls)
- approval options: once / 10 minutes / always for repo / deny

**FR-17:** Store approvals as scoped grants:
- time-bound
- repo-bound
- command-pattern-bound (optional, admin-only)

### 8.6 Logging & Audit
**FR-18:** Log every evaluated event (LLM/API + command), with:
- decision, policy_id, reason_codes, risk_score
- content hashes (not raw content by default), redaction actions
- destination metadata
- approver identity if applicable

**FR-19:** Local encrypted storage + optional export:
- OTLP / syslog / JSON lines
- SIEM-friendly schema

**FR-20:** Optional tamper-evidence (hash chaining) for audit logs.

---

## 9. Default Policy Packs (v1)

### 9.1 Proxy Policies
- **Conservative:** block unknown providers, require approval for attachments and code, strict secrets/PII rules.
- **Balanced:** allow common providers, redact PII, approval for attachments and risky content.
- **Developer-friendly:** log-only for some categories, block only secrets and explicit disallowed endpoints.

### 9.2 Command Policies
**Auto-approve examples:**
- `ls`, `pwd`, `cat README.md`
- `git status`, `git diff`, `git log`
- `npm test`, `pnpm lint`, `pytest` (no installs/network)

**Require approval examples:**
- installs: `npm install`, `pip install`, `brew install`, `apt install`, `choco install`
- destructive: `rm -rf`, `find ... -delete`, wide globs with in-place edits
- network: `curl`, `wget`, `scp`, `rsync`, `aws s3 cp`, `gh release upload`
- sensitive reads: `.env`, credential stores, `~/.ssh`

**Block examples:**
- `curl ... | sh`, `wget ... | bash`, PowerShell remote execution patterns
- disk wipe / system destruction patterns (`mkfs`, `dd` to raw devices, `rm -rf /`)
- explicit credential exfil patterns

**Rewrite examples (Allow with changes):**
- `git clean -fdx` → enforce `git clean -ndx` first
- `terraform apply` → enforce `terraform plan` first
- `rm -rf <dir>` → convert to dry-run or require interactive confirmation flag where possible

---

## 10. Non-functional Requirements

**NFR-1 (Latency):**
- deterministic scan: target < 20ms typical
- Ollama scoring: configurable; “fast mode” target < 250ms median on common dev hardware

**NFR-2 (Reliability):**
- fail-open vs fail-closed configurable per policy pack
- graceful degradation when proxy visibility is limited

**NFR-3 (Security):**
- signed binaries/updates
- least privilege
- secure storage for config/certs/log encryption keys
- safe redaction by default (no raw secrets in logs)

**NFR-4 (Privacy):**
- never send content externally except to approved upstream providers
- keep local risk scoring local

**NFR-5 (Compatibility):**
- macOS/Windows/Linux installers
- system proxy integration where supported
- hook integrations documented and tested

---

## 11. Technical Architecture (High Level)

### 11.1 Components
1. **ninjashieldd (Daemon)**
   - local HTTP API (decision engine)
   - policy evaluation
   - risk scoring orchestration (deterministic + optional Ollama)
   - audit logging and exports

2. **Proxy Listener**
   - HTTP proxy endpoint
   - optional TLS interception mode (explicit user enablement)
   - provider adapters and normalizer

3. **Hook Runtimes**
   - **Claude Code hook script** that calls `ninjashieldd`
   - **Codex rules generator** and config helper

4. **UI**
   - tray/menu bar UI (optional v1, but recommended)
   - terminal UI for approvals (must-have if GUI not present)

### 11.2 Key APIs (Local)
- `POST /v1/llm/evaluate` → decision + redactions/transformations
- `POST /v1/commands/evaluate` → allow/ask/deny + rewrite + reasons
- `GET /v1/policy` → active policy pack
- `POST /v1/approvals/grant` → store scoped approvals
- `GET /v1/events/recent` → recent events for UI

---

## 12. Data Model (Audit Event)

### 12.1 Common fields
- `event_id`, `timestamp`, `user`, `machine_id`, `tool` (claude_code/codex/other)
- `decision` (ALLOW/ASK/DENY/REDACT/TRANSFORM)
- `policy_id`, `reason_codes[]`, `risk_score`, `risk_categories[]`
- `content_hash` (hash of normalized payload, post-redaction)

### 12.2 LLM event fields
- `provider`, `model`, `endpoint`, `request_type`
- `attachments_present` (bool), `attachment_types[]`
- `redactions_applied[]`, `transformations_applied[]`

### 12.3 Command event fields
- `command_argv[]`, `cwd`, `repo_root`
- `rewrite_applied` (bool), `rewritten_argv[]` (masked if needed)

---

## 13. Distribution & Packaging

### 13.1 Open Source Layout (suggested)
- `cmd/ninjashield` (CLI)
- `cmd/ninjashieldd` (daemon)
- `pkg/policy` (policy engine)
- `pkg/scanners` (deterministic scanners)
- `pkg/ollama` (optional scorer)
- `integrations/claude-code/` (hook scripts + docs)
- `integrations/codex/` (rules compiler + docs)

### 13.2 Config
- `~/.ninjashield/config.yaml`
- project overrides in repo: `.ninjashield/policy.yaml`

---

## 14. Rollout Plan

### Phase 1 (MVP)
- SDK/local gateway mode (OpenAI-compatible facade)
- deterministic scanners + policy engine
- Claude Code hook integration (Bash gating)
- local approval prompt (TUI)
- encrypted audit logs

### Phase 2
- system proxy mode + basic endpoint detection
- optional TLS interception mode
- Codex policy compiler (rules + config)
- SIEM export (OTLP/JSON)

### Phase 3
- richer UI (tray/menu bar), team policy sync, admin console (optional)
- advanced provenance (tamper-evident logs), enterprise deployments

---

## 15. Success Metrics

- **Coverage:** % of LLM/API calls governed (proxy + SDK mode)
- **Safety:** # of prevented secret/PII exfil events
- **Command safety:** # risky commands caught; approval vs deny rates
- **False positives:** override rate, time-to-unblock
- **Performance:** median added latency per request/command
- **Adoption:** # integrated tools/projects using hooks/SDK

---

## 16. Risks & Mitigations

- **TLS pinning limits proxy visibility** → mitigate with SDK mode + clear UX warnings.
- **LLM risk scoring inconsistency** → mitigate with deterministic hard-block rules and conservative defaults.
- **User frustration from prompts** → mitigate with scoped/time-bound approvals, clear reason codes, and safe rewrites.
- **Policy drift across tools** → mitigate with single canonical policy + compilers for Claude/Codex.

---

## 17. Appendix

### A. One-liner
**NinjaShield is a local AI firewall that proxies LLM/API traffic and gates agent commands—auto-approving safe actions and requiring human approval for risky ones.**

### B. Module names
- **NinjaShield Proxy** — LLM/API firewall & proxy
- **NinjaShield Gate** — Claude Code/Codex command approvals
- **NinjaShield Audit** — logging & SIEM export
- **NinjaShield Scan** — optional Ollama risk scoring

