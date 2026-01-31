#!/bin/bash
# Test script for NinjaShield Claude Code hook

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_SCRIPT="$SCRIPT_DIR/hook.sh"

echo "NinjaShield Claude Code Hook Tests"
echo "==================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}PASS${NC}: $1"
}

fail() {
    echo -e "${RED}FAIL${NC}: $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}WARN${NC}: $1"
}

# Test 1: Non-Bash tool (should allow)
test_non_bash_tool() {
    echo "Test 1: Non-Bash tool (should allow)"

    INPUT='{"tool_name":"Read","tool_input":{"file_path":"/tmp/test.txt"},"cwd":"/tmp"}'
    RESULT=$(echo "$INPUT" | "$HOOK_SCRIPT")
    DECISION=$(echo "$RESULT" | jq -r '.permissionDecision')

    if [ "$DECISION" = "allow" ]; then
        pass "Non-Bash tools are allowed"
    else
        fail "Expected 'allow' for non-Bash tool, got '$DECISION'"
    fi
}

# Test 2: Empty command (should allow)
test_empty_command() {
    echo "Test 2: Empty command (should allow)"

    INPUT='{"tool_name":"Bash","tool_input":{},"cwd":"/tmp"}'
    RESULT=$(echo "$INPUT" | "$HOOK_SCRIPT")
    DECISION=$(echo "$RESULT" | jq -r '.permissionDecision')

    if [ "$DECISION" = "allow" ]; then
        pass "Empty commands are allowed"
    else
        fail "Expected 'allow' for empty command, got '$DECISION'"
    fi
}

# Test 3: Simple allowed command (requires daemon)
test_simple_command() {
    echo "Test 3: Simple allowed command (requires daemon)"

    if ! curl -s --connect-timeout 1 "http://localhost:7575/health" > /dev/null 2>&1; then
        warn "NinjaShield daemon not running - skipping"
        return
    fi

    INPUT='{"tool_name":"Bash","tool_input":{"command":"ls -la"},"cwd":"/tmp"}'
    RESULT=$(echo "$INPUT" | "$HOOK_SCRIPT")
    DECISION=$(echo "$RESULT" | jq -r '.permissionDecision')

    if [ "$DECISION" = "allow" ]; then
        pass "Simple 'ls' command is allowed"
    else
        fail "Expected 'allow' for 'ls' command, got '$DECISION'"
    fi
}

# Test 4: Dangerous command (requires daemon)
test_dangerous_command() {
    echo "Test 4: Dangerous command (requires daemon)"

    if ! curl -s --connect-timeout 1 "http://localhost:7575/health" > /dev/null 2>&1; then
        warn "NinjaShield daemon not running - skipping"
        return
    fi

    INPUT='{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/tmp"}'
    RESULT=$(echo "$INPUT" | "$HOOK_SCRIPT")
    DECISION=$(echo "$RESULT" | jq -r '.permissionDecision')

    if [ "$DECISION" = "deny" ] || [ "$DECISION" = "ask" ]; then
        pass "Dangerous 'rm -rf /' command is blocked/asked (got '$DECISION')"
    else
        fail "Expected 'deny' or 'ask' for dangerous command, got '$DECISION'"
    fi
}

# Test 5: Command with secrets (requires daemon)
test_secret_command() {
    echo "Test 5: Command with potential secrets (requires daemon)"

    if ! curl -s --connect-timeout 1 "http://localhost:7575/health" > /dev/null 2>&1; then
        warn "NinjaShield daemon not running - skipping"
        return
    fi

    INPUT='{"tool_name":"Bash","tool_input":{"command":"echo sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"},"cwd":"/tmp"}'
    RESULT=$(echo "$INPUT" | "$HOOK_SCRIPT")
    DECISION=$(echo "$RESULT" | jq -r '.permissionDecision')
    RISK_SCORE=$(echo "$RESULT" | jq -r '.metadata.risk_score // 0')

    echo "  Decision: $DECISION, Risk Score: $RISK_SCORE"

    if [ "$DECISION" = "deny" ] || [ "$DECISION" = "ask" ]; then
        pass "Command with API key is blocked/asked"
    else
        warn "Command with API key was allowed (risk score: $RISK_SCORE)"
    fi
}

# Test 6: Daemon not running (should ask)
test_daemon_not_running() {
    echo "Test 6: Behavior when daemon is not running"

    # Temporarily set a different port to simulate daemon not running
    export NINJASHIELD_PORT=9999

    INPUT='{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/tmp"}'
    RESULT=$(echo "$INPUT" | "$HOOK_SCRIPT")
    DECISION=$(echo "$RESULT" | jq -r '.permissionDecision')
    MESSAGE=$(echo "$RESULT" | jq -r '.message // empty')

    unset NINJASHIELD_PORT

    if [ "$DECISION" = "ask" ]; then
        pass "When daemon is not running, defaults to 'ask'"
        if [ -n "$MESSAGE" ]; then
            echo "  Message: $MESSAGE"
        fi
    else
        fail "Expected 'ask' when daemon not running, got '$DECISION'"
    fi
}

# Run all tests
echo ""
test_non_bash_tool
echo ""
test_empty_command
echo ""
test_simple_command
echo ""
test_dangerous_command
echo ""
test_secret_command
echo ""
test_daemon_not_running
echo ""

echo "==================================="
echo "All tests completed!"
