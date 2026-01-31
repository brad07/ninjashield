#!/bin/bash
# Test script for NinjaShield Ollama integration
set -e

OLLAMA_MODEL="${OLLAMA_MODEL:-gemma3}"
NINJA_PORT="${NINJA_PORT:-7575}"
NINJA_HOST="http://localhost:$NINJA_PORT"

echo "=== NinjaShield Ollama Integration Test ==="
echo "Model: $OLLAMA_MODEL"
echo ""

# Check if Ollama is running
echo "1. Checking Ollama availability..."
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "   ✓ Ollama is running"
else
    echo "   ✗ Ollama is not running. Start it with: ollama serve"
    exit 1
fi

# Check if model is available
echo ""
echo "2. Checking if $OLLAMA_MODEL model is available..."
if ollama list | grep -q "$OLLAMA_MODEL"; then
    echo "   ✓ Model $OLLAMA_MODEL is available"
else
    echo "   ✗ Model $OLLAMA_MODEL not found. Pulling..."
    ollama pull $OLLAMA_MODEL
fi

# Build NinjaShield
echo ""
echo "3. Building NinjaShield..."
go build -o bin/ninjashieldd ./cmd/ninjashieldd
echo "   ✓ Build successful"

# Start NinjaShield daemon in background
echo ""
echo "4. Starting NinjaShield daemon with Ollama..."
./bin/ninjashieldd --ollama --ollama-model=$OLLAMA_MODEL &
NINJA_PID=$!
sleep 2

# Cleanup function
cleanup() {
    echo ""
    echo "Stopping NinjaShield daemon..."
    kill $NINJA_PID 2>/dev/null || true
}
trap cleanup EXIT

# Check if daemon started
if ! curl -s "$NINJA_HOST/health" > /dev/null 2>&1; then
    echo "   ✗ Failed to start daemon"
    exit 1
fi
echo "   ✓ Daemon running on port $NINJA_PORT"

# Run tests
echo ""
echo "5. Running LLM evaluation tests..."
echo ""

# Test 1: Simple allowed request
echo "--- Test 1: Simple request (should be ALLOW) ---"
RESULT=$(curl -s -X POST "$NINJA_HOST/v1/llm/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "body": {
      "model": "gpt-4",
      "messages": [{"role": "user", "content": "What is 2+2?"}]
    }
  }')
echo "$RESULT" | jq -r '"Decision: \(.decision), Risk Score: \(.risk_score)"'
echo "$RESULT" | jq -r 'if .context then "Context: \(.context)" else empty end'
echo ""

# Test 2: Request with secrets
echo "--- Test 2: Request with API key (should be DENY) ---"
RESULT=$(curl -s -X POST "$NINJA_HOST/v1/llm/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "body": {
      "model": "gpt-4",
      "messages": [{"role": "user", "content": "Use this key: sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"}]
    }
  }')
echo "$RESULT" | jq -r '"Decision: \(.decision), Risk Score: \(.risk_score)"'
echo "$RESULT" | jq -r '"Risk Categories: \(.risk_categories | join(", "))"'
echo ""

# Test 3: Request with PII
echo "--- Test 3: Request with PII (should be ASK) ---"
RESULT=$(curl -s -X POST "$NINJA_HOST/v1/llm/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "body": {
      "model": "gpt-4",
      "messages": [{"role": "user", "content": "My SSN is 123-45-6789 and email is john@example.com"}]
    }
  }')
echo "$RESULT" | jq -r '"Decision: \(.decision), Risk Score: \(.risk_score)"'
echo "$RESULT" | jq -r '"Risk Categories: \(.risk_categories | join(", "))"'
echo ""

# Test 4: Unknown provider
echo "--- Test 4: Unknown provider (should be DENY) ---"
RESULT=$(curl -s -X POST "$NINJA_HOST/v1/llm/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "sketchy-provider",
    "body": {
      "model": "unknown-model",
      "messages": [{"role": "user", "content": "Hello"}]
    }
  }')
echo "$RESULT" | jq -r '"Decision: \(.decision), Risk Score: \(.risk_score)"'
echo "$RESULT" | jq -r '"Reason Codes: \(.reason_codes | join(", "))"'
echo ""

# Test 5: Request with attachments
echo "--- Test 5: Request with attachments (should be ASK) ---"
RESULT=$(curl -s -X POST "$NINJA_HOST/v1/llm/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "body": {
      "model": "gpt-4-vision",
      "messages": [{
        "role": "user",
        "content": [
          {"type": "text", "text": "What is in this image?"},
          {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}
        ]
      }]
    }
  }')
echo "$RESULT" | jq -r '"Decision: \(.decision), Risk Score: \(.risk_score)"'
echo ""

# Test 6: Anthropic provider
echo "--- Test 6: Anthropic provider (should be ALLOW) ---"
RESULT=$(curl -s -X POST "$NINJA_HOST/v1/llm/evaluate" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "anthropic",
    "body": {
      "model": "claude-3-opus",
      "messages": [{"role": "user", "content": "Hello Claude!"}]
    }
  }')
echo "$RESULT" | jq -r '"Decision: \(.decision), Risk Score: \(.risk_score)"'
echo ""

# Check stats
echo "--- Server Stats ---"
curl -s "$NINJA_HOST/v1/stats" | jq '.'
echo ""

echo "=== All tests completed! ==="
