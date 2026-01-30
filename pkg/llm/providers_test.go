package llm

import (
	"encoding/json"
	"testing"
)

func TestDetectProvider(t *testing.T) {
	tests := []struct {
		url      string
		expected Provider
	}{
		{"https://api.openai.com/v1/chat/completions", ProviderOpenAI},
		{"https://api.anthropic.com/v1/messages", ProviderAnthropic},
		{"https://myresource.openai.azure.com/openai/deployments/gpt-4", ProviderAzure},
		{"https://generativelanguage.googleapis.com/v1beta/models", ProviderGoogle},
		{"http://localhost:11434/api/chat", ProviderOllama},
		{"http://127.0.0.1:11434/api/generate", ProviderOllama},
		{"https://unknown-api.com/v1/chat", ProviderUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			info := DetectProvider(tt.url)
			if info.Provider != tt.expected {
				t.Errorf("DetectProvider(%s) = %v, want %v", tt.url, info.Provider, tt.expected)
			}
		})
	}
}

func TestDetectRequestType(t *testing.T) {
	tests := []struct {
		path     string
		expected RequestType
	}{
		{"/v1/chat/completions", RequestTypeChat},
		{"/v1/completions", RequestTypeCompletion},
		{"/v1/embeddings", RequestTypeEmbedding},
		{"/v1/images/generations", RequestTypeImage},
		{"/v1/audio/transcriptions", RequestTypeAudio},
		{"/v1/files", RequestTypeFile},
		{"/v1/messages", RequestTypeChat}, // Anthropic
		{"/unknown/endpoint", RequestTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := DetectRequestType(tt.path)
			if result != tt.expected {
				t.Errorf("DetectRequestType(%s) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestParser_ParseOpenAIRequest(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "You are a helpful assistant."},
			{"role": "user", "content": "Hello!"}
		],
		"temperature": 0.7,
		"max_tokens": 1000,
		"stream": false
	}`

	req, err := parser.ParseRequest(ProviderOpenAI, "/v1/chat/completions", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	if req.Provider != ProviderOpenAI {
		t.Errorf("Provider = %v, want %v", req.Provider, ProviderOpenAI)
	}

	if req.Model != "gpt-4" {
		t.Errorf("Model = %v, want gpt-4", req.Model)
	}

	if len(req.Messages) != 2 {
		t.Errorf("Messages count = %d, want 2", len(req.Messages))
	}

	if req.Messages[0].Role != RoleSystem {
		t.Errorf("First message role = %v, want system", req.Messages[0].Role)
	}

	if req.Temperature == nil || *req.Temperature != 0.7 {
		t.Error("Temperature not parsed correctly")
	}

	if req.MaxTokens == nil || *req.MaxTokens != 1000 {
		t.Error("MaxTokens not parsed correctly")
	}
}

func TestParser_ParseOpenAIRequestWithTools(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "What's the weather?"}
		],
		"tools": [
			{
				"type": "function",
				"function": {
					"name": "get_weather",
					"description": "Get current weather",
					"parameters": {"type": "object"}
				}
			}
		]
	}`

	req, err := parser.ParseRequest(ProviderOpenAI, "/v1/chat/completions", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	if len(req.Tools) != 1 {
		t.Errorf("Tools count = %d, want 1", len(req.Tools))
	}

	if req.Tools[0].Function.Name != "get_weather" {
		t.Errorf("Tool name = %v, want get_weather", req.Tools[0].Function.Name)
	}
}

func TestParser_ParseAnthropicRequest(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "claude-3-opus-20240229",
		"max_tokens": 1024,
		"system": "You are a helpful assistant.",
		"messages": [
			{"role": "user", "content": "Hello, Claude!"}
		]
	}`

	req, err := parser.ParseRequest(ProviderAnthropic, "/v1/messages", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	if req.Provider != ProviderAnthropic {
		t.Errorf("Provider = %v, want %v", req.Provider, ProviderAnthropic)
	}

	if req.Model != "claude-3-opus-20240229" {
		t.Errorf("Model = %v, want claude-3-opus-20240229", req.Model)
	}

	if req.SystemPrompt != "You are a helpful assistant." {
		t.Errorf("SystemPrompt = %v, want 'You are a helpful assistant.'", req.SystemPrompt)
	}

	if len(req.Messages) != 1 {
		t.Errorf("Messages count = %d, want 1", len(req.Messages))
	}
}

func TestParser_ParseOllamaRequest(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "llama3.2",
		"messages": [
			{"role": "user", "content": "Hello!"}
		],
		"stream": false
	}`

	req, err := parser.ParseRequest(ProviderOllama, "/api/chat", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	if req.Provider != ProviderOllama {
		t.Errorf("Provider = %v, want %v", req.Provider, ProviderOllama)
	}

	if req.Model != "llama3.2" {
		t.Errorf("Model = %v, want llama3.2", req.Model)
	}

	if len(req.Messages) != 1 {
		t.Errorf("Messages count = %d, want 1", len(req.Messages))
	}

	if req.Stream {
		t.Error("Stream should be false")
	}
}

func TestParser_ParseOllamaGenerateRequest(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "llama3.2",
		"prompt": "Hello, how are you?",
		"system": "You are helpful.",
		"stream": true
	}`

	req, err := parser.ParseRequest(ProviderOllama, "/api/generate", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	if req.Prompt != "Hello, how are you?" {
		t.Errorf("Prompt = %v, want 'Hello, how are you?'", req.Prompt)
	}

	if req.SystemPrompt != "You are helpful." {
		t.Errorf("SystemPrompt = %v, want 'You are helpful.'", req.SystemPrompt)
	}

	if !req.Stream {
		t.Error("Stream should be true")
	}
}

func TestParser_ParseGenericRequest(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "some-model",
		"custom_field": "value"
	}`

	req, err := parser.ParseRequest(ProviderUnknown, "/v1/unknown", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	if req.Provider != ProviderUnknown {
		t.Errorf("Provider = %v, want %v", req.Provider, ProviderUnknown)
	}

	if req.Model != "some-model" {
		t.Errorf("Model = %v, want some-model", req.Model)
	}
}

func TestExtractContent(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"string", "hello world", "hello world"},
		{"content parts", []interface{}{
			map[string]interface{}{"type": "text", "text": "part1"},
			map[string]interface{}{"type": "text", "text": "part2"},
		}, "part1\npart2"},
		{"nil", nil, ""},
		{"number", 123, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractContent(tt.input)
			if result != tt.expected {
				t.Errorf("extractContent(%v) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestExtractStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{"single string", "stop", []string{"stop"}},
		{"string slice", []string{"stop1", "stop2"}, []string{"stop1", "stop2"}},
		{"interface slice", []interface{}{"a", "b"}, []string{"a", "b"}},
		{"nil", nil, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractStringSlice(tt.input)
			if !sliceEqual(result, tt.expected) {
				t.Errorf("extractStringSlice(%v) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParser_InvalidJSON(t *testing.T) {
	parser := NewParser()

	_, err := parser.ParseRequest(ProviderOpenAI, "/v1/chat/completions", []byte("not json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestRequest_GetAllContent_WithParsedRequest(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "system", "content": "Be helpful."},
			{"role": "user", "content": "Hello!"},
			{"role": "assistant", "content": "Hi there!"}
		]
	}`

	req, err := parser.ParseRequest(ProviderOpenAI, "/v1/chat/completions", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	content := req.GetAllContent()

	if !containsString(content, "Be helpful") {
		t.Error("Content should contain system message")
	}
	if !containsString(content, "Hello") {
		t.Error("Content should contain user message")
	}
	if !containsString(content, "Hi there") {
		t.Error("Content should contain assistant message")
	}
}

// Test that parsed requests can be serialized back to JSON
func TestParsedRequest_JSON(t *testing.T) {
	parser := NewParser()

	body := `{
		"model": "gpt-4",
		"messages": [
			{"role": "user", "content": "Hello!"}
		],
		"temperature": 0.7
	}`

	req, err := parser.ParseRequest(ProviderOpenAI, "/v1/chat/completions", []byte(body))
	if err != nil {
		t.Fatalf("ParseRequest failed: %v", err)
	}

	// Should be serializable
	_, err = json.Marshal(req)
	if err != nil {
		t.Errorf("Failed to marshal parsed request: %v", err)
	}
}
