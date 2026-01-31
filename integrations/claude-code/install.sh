#!/bin/bash
# NinjaShield Claude Code Integration Installer
# This script sets up the NinjaShield hook for Claude Code

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK_SCRIPT="$SCRIPT_DIR/hook.sh"
CLAUDE_SETTINGS_DIR="$HOME/.claude"
CLAUDE_SETTINGS_FILE="$CLAUDE_SETTINGS_DIR/settings.json"

echo "NinjaShield Claude Code Integration Installer"
echo "=============================================="
echo ""

# Check dependencies
check_dependencies() {
    local missing=()

    if ! command -v jq &> /dev/null; then
        missing+=("jq")
    fi

    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo "Error: Missing required dependencies: ${missing[*]}"
        echo "Please install them and try again."
        echo ""
        echo "On macOS: brew install ${missing[*]}"
        echo "On Ubuntu: sudo apt install ${missing[*]}"
        exit 1
    fi
}

# Make hook script executable
setup_hook_script() {
    chmod +x "$HOOK_SCRIPT"
    echo "Made hook script executable: $HOOK_SCRIPT"
}

# Create or update Claude settings
configure_claude_settings() {
    # Create settings directory if it doesn't exist
    mkdir -p "$CLAUDE_SETTINGS_DIR"

    # Define the hook configuration
    local hook_config=$(cat <<EOF
{
    "hooks": {
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "$HOOK_SCRIPT"
                    }
                ]
            }
        ]
    }
}
EOF
)

    if [ -f "$CLAUDE_SETTINGS_FILE" ]; then
        echo "Found existing settings file: $CLAUDE_SETTINGS_FILE"

        # Check if hooks already exist
        if jq -e '.hooks' "$CLAUDE_SETTINGS_FILE" > /dev/null 2>&1; then
            echo ""
            echo "Warning: Your settings.json already has hooks configured."
            echo "To avoid conflicts, please manually add the NinjaShield hook."
            echo ""
            echo "Add this to your hooks.PreToolUse array:"
            echo ""
            echo '    {'
            echo '        "matcher": "Bash",'
            echo '        "hooks": ['
            echo '            {'
            echo '                "type": "command",'
            echo "                \"command\": \"$HOOK_SCRIPT\""
            echo '            }'
            echo '        ]'
            echo '    }'
            echo ""
            return 0
        fi

        # Merge hooks into existing settings
        echo "Adding NinjaShield hooks to existing settings..."
        local temp_file=$(mktemp)
        jq --argjson hooks "$hook_config" '. + $hooks' "$CLAUDE_SETTINGS_FILE" > "$temp_file"
        mv "$temp_file" "$CLAUDE_SETTINGS_FILE"
        echo "Updated: $CLAUDE_SETTINGS_FILE"
    else
        echo "Creating new settings file: $CLAUDE_SETTINGS_FILE"
        echo "$hook_config" | jq '.' > "$CLAUDE_SETTINGS_FILE"
        echo "Created: $CLAUDE_SETTINGS_FILE"
    fi
}

# Verify NinjaShield daemon
check_ninjashield() {
    echo ""
    echo "Checking NinjaShield daemon..."

    if curl -s --connect-timeout 2 "http://localhost:7575/health" > /dev/null 2>&1; then
        echo "NinjaShield daemon is running."
    else
        echo "NinjaShield daemon is not running."
        echo ""
        echo "To start the daemon, run:"
        echo "  ninjashieldd"
        echo ""
        echo "Or with Ollama-based risk scoring:"
        echo "  ninjashieldd --ollama"
    fi
}

# Print success message
print_success() {
    echo ""
    echo "=============================================="
    echo "Installation complete!"
    echo ""
    echo "How it works:"
    echo "  1. Claude Code will now send Bash commands to NinjaShield before execution"
    echo "  2. NinjaShield evaluates the command against the active policy"
    echo "  3. Based on the decision (ALLOW/DENY/ASK), Claude Code will:"
    echo "     - ALLOW: Execute the command"
    echo "     - DENY: Block the command"
    echo "     - ASK: Prompt you for confirmation"
    echo ""
    echo "Configuration:"
    echo "  Hook script: $HOOK_SCRIPT"
    echo "  Settings file: $CLAUDE_SETTINGS_FILE"
    echo ""
    echo "Environment variables (optional):"
    echo "  NINJASHIELD_HOST    - Daemon host (default: localhost)"
    echo "  NINJASHIELD_PORT    - Daemon port (default: 7575)"
    echo "  NINJASHIELD_TIMEOUT - Request timeout in seconds (default: 5)"
    echo ""
    echo "To uninstall, remove the NinjaShield hook from:"
    echo "  $CLAUDE_SETTINGS_FILE"
    echo ""
}

# Main
main() {
    check_dependencies
    setup_hook_script
    configure_claude_settings
    check_ninjashield
    print_success
}

main "$@"
