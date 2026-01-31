#!/bin/bash
# NinjaShield Claude Code Hook
# This script integrates NinjaShield with Claude Code via PreToolUse hooks.
#
# Installation: Add to ~/.claude/settings.json under "hooks"
# See README.md for configuration details.

set -e

# Debug logging
echo "[$(date)] Hook called" >> /tmp/ninjashield-hook.log

# Configuration - can be overridden via environment variables
NINJASHIELD_HOST="${NINJASHIELD_HOST:-localhost}"
NINJASHIELD_PORT="${NINJASHIELD_PORT:-7575}"
NINJASHIELD_URL="${NINJASHIELD_URL:-http://${NINJASHIELD_HOST}:${NINJASHIELD_PORT}}"
NINJASHIELD_TIMEOUT="${NINJASHIELD_TIMEOUT:-15}"

# Helper function to output hook response in correct format
output_response() {
    local decision="$1"
    local reason="$2"

    local output
    if [ -n "$reason" ]; then
        output=$(jq -n \
            --arg decision "$decision" \
            --arg reason "$reason" \
            '{
                hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: $decision,
                    permissionDecisionReason: $reason
                }
            }')
    else
        output=$(jq -n \
            --arg decision "$decision" \
            '{
                hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: $decision
                }
            }')
    fi

    echo "[$(date)] Output: $output" >> /tmp/ninjashield-hook.log
    echo "$output"
}

# Read hook input from stdin
HOOK_INPUT=$(cat)
echo "[$(date)] Input: $HOOK_INPUT" >> /tmp/ninjashield-hook.log

# Extract tool name and input from the hook context
TOOL_NAME=$(echo "$HOOK_INPUT" | jq -r '.tool_name // empty')
TOOL_INPUT=$(echo "$HOOK_INPUT" | jq -r '.tool_input // empty')
SESSION_ID=$(echo "$HOOK_INPUT" | jq -r '.session_id // empty')
CWD=$(echo "$HOOK_INPUT" | jq -r '.cwd // empty')

# Only process Bash tool calls
if [ "$TOOL_NAME" != "Bash" ]; then
    # Allow all non-Bash tools
    output_response "allow" ""
    exit 0
fi

# Extract the command from Bash tool input
COMMAND=$(echo "$TOOL_INPUT" | jq -r '.command // empty')

if [ -z "$COMMAND" ]; then
    # No command found, allow by default
    output_response "allow" ""
    exit 0
fi

# Build the evaluation request
REQUEST_BODY=$(jq -n \
    --arg command "$COMMAND" \
    --arg cwd "$CWD" \
    --arg tool "claude_code" \
    --arg user "${USER:-$(whoami)}" \
    --arg repo_root "${CWD}" \
    '{
        command: $command,
        cwd: $cwd,
        tool: $tool,
        user: $user,
        repo_root: $repo_root
    }')

# Check if NinjaShield is available
if ! curl -s --connect-timeout 1 "${NINJASHIELD_URL}/health" > /dev/null 2>&1; then
    # NinjaShield not available - FAIL CLOSED (deny)
    output_response "deny" "NinjaShield daemon is not running. Start it with: ninjashieldd"
    exit 0
fi

# Call NinjaShield for evaluation
# Use -m for total max time (allows for AI evaluation), --connect-timeout for initial connection
RESPONSE=$(curl -s --connect-timeout 2 -m "$NINJASHIELD_TIMEOUT" \
    -X POST "${NINJASHIELD_URL}/v1/commands/evaluate" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY" 2>&1) || {
    # Request failed - FAIL CLOSED (deny)
    output_response "deny" "Failed to contact NinjaShield daemon"
    exit 0
}

# Parse the NinjaShield response
DECISION=$(echo "$RESPONSE" | jq -r '.decision // "ASK"')
RISK_SCORE=$(echo "$RESPONSE" | jq -r '.risk_score // 0')
CONTEXT=$(echo "$RESPONSE" | jq -r '.context // empty')
REASON_CODES=$(echo "$RESPONSE" | jq -r '.reason_codes // []')
SUGGESTED_REWRITE=$(echo "$RESPONSE" | jq -r '.rewrite.suggested // empty')

# Map NinjaShield decisions to Claude Code permission decisions
case "$DECISION" in
    "ALLOW")
        output_response "allow" ""
        ;;
    "DENY")
        # Ask user for approval instead of hard blocking, but show warning
        if [ -n "$CONTEXT" ] && [ "$CONTEXT" != "null" ]; then
            output_response "ask" "⚠️ NINJASHIELD DENIED (Risk: $RISK_SCORE) - $CONTEXT"
        else
            output_response "ask" "⚠️ NINJASHIELD DENIED (Risk: $RISK_SCORE) - Command flagged by security policy"
        fi
        ;;
    "REDACT")
        # If there's a suggested rewrite, use it via updatedInput
        if [ -n "$SUGGESTED_REWRITE" ] && [ "$SUGGESTED_REWRITE" != "null" ]; then
            # Return the modified command with allow
            OUTPUT=$(jq -n \
                --arg command "$SUGGESTED_REWRITE" \
                '{
                    hookSpecificOutput: {
                        hookEventName: "PreToolUse",
                        permissionDecision: "allow",
                        updatedInput: {command: $command}
                    }
                }')
            echo "[$(date)] Output: $OUTPUT" >> /tmp/ninjashield-hook.log
            echo "$OUTPUT"
            exit 0
        fi
        # Fall through to ask if no rewrite available
        if [ -n "$CONTEXT" ] && [ "$CONTEXT" != "null" ]; then
            output_response "ask" "[NinjaShield Risk: $RISK_SCORE] $CONTEXT"
        else
            output_response "ask" "[NinjaShield Risk: $RISK_SCORE] Command requires approval"
        fi
        ;;
    "ASK"|*)
        if [ -n "$CONTEXT" ] && [ "$CONTEXT" != "null" ]; then
            output_response "ask" "[NinjaShield Risk: $RISK_SCORE] $CONTEXT"
        else
            output_response "ask" ""
        fi
        ;;
esac
