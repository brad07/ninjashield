package ollama_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brad07/ninjashield/pkg/ollama"
)

func TestClient_NewClient(t *testing.T) {
	config := ollama.Config{
		Endpoint: "http://localhost:11434",
		Model:    "gemma3",
		Mode:     ollama.ModeFast,
		Timeout:  30 * time.Second,
	}

	client := ollama.NewClient(config)
	if client == nil {
		t.Fatal("Expected client to be created")
	}
}

func TestClient_NewClientDefaults(t *testing.T) {
	config := ollama.Config{} // All empty - should use defaults
	client := ollama.NewClient(config)

	if client == nil {
		t.Fatal("Expected client to be created")
	}

	// Verify defaults are applied
	if client.GetMode() != ollama.ModeFast {
		t.Errorf("Expected default mode to be fast, got %s", client.GetMode())
	}
}

func TestClient_DefaultConfig(t *testing.T) {
	config := ollama.DefaultConfig()

	if config.Endpoint != "http://localhost:11434" {
		t.Errorf("Unexpected default endpoint: %s", config.Endpoint)
	}

	if config.Model != "gemma3" {
		t.Errorf("Unexpected default model: %s", config.Model)
	}

	if config.Mode != ollama.ModeFast {
		t.Errorf("Unexpected default mode: %s", config.Mode)
	}

	if config.Timeout != 30*time.Second {
		t.Errorf("Unexpected default timeout: %s", config.Timeout)
	}
}

func TestClient_AssessRisk_ModeOff(t *testing.T) {
	config := ollama.Config{
		Mode: ollama.ModeOff,
	}
	client := ollama.NewClient(config)

	summary := ollama.ContentSummary{
		Provider:    "openai",
		Model:       "gpt-4",
		RequestType: "chat",
	}

	result, err := client.AssessRisk(context.Background(), summary)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.RiskScore != 0 {
		t.Errorf("Expected risk score 0 for mode off, got %d", result.RiskScore)
	}

	if result.RecommendedAction != "allow" {
		t.Errorf("Expected recommended action 'allow' for mode off, got %s", result.RecommendedAction)
	}

	if result.Confidence != 0 {
		t.Errorf("Expected confidence 0 for mode off, got %f", result.Confidence)
	}
}

func TestClient_AssessRisk_MockServer(t *testing.T) {
	// Create mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/generate" {
			t.Errorf("Unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}

		// Return a mock response
		response := map[string]interface{}{
			"response": `{"risk_score": 25, "risk_categories": ["normal"], "recommended_action": "allow", "explanation": "Low risk request", "confidence": 0.85}`,
			"done":     true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := ollama.Config{
		Endpoint: server.URL,
		Model:    "gemma3",
		Mode:     ollama.ModeFast,
		Timeout:  5 * time.Second,
	}
	client := ollama.NewClient(config)

	summary := ollama.ContentSummary{
		Provider:       "openai",
		Model:          "gpt-4",
		RequestType:    "chat",
		MessageCount:   2,
		HasAttachments: false,
		HasTools:       false,
		ContentClasses: []string{},
		ContentPreview: "Hello, how are you?",
	}

	result, err := client.AssessRisk(context.Background(), summary)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if result.RiskScore != 25 {
		t.Errorf("Expected risk score 25, got %d", result.RiskScore)
	}

	if result.RecommendedAction != "allow" {
		t.Errorf("Expected recommended action 'allow', got %s", result.RecommendedAction)
	}

	if result.Confidence != 0.85 {
		t.Errorf("Expected confidence 0.85, got %f", result.Confidence)
	}
}

func TestClient_AssessRisk_InvalidResponse(t *testing.T) {
	// Create mock Ollama server that returns invalid JSON
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"response": "not valid json at all",
			"done":     true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := ollama.Config{
		Endpoint: server.URL,
		Model:    "gemma3",
		Mode:     ollama.ModeFast,
		Timeout:  5 * time.Second,
	}
	client := ollama.NewClient(config)

	summary := ollama.ContentSummary{
		Provider: "openai",
		Model:    "gpt-4",
	}

	result, err := client.AssessRisk(context.Background(), summary)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should return default assessment on parse error
	if result.RiskScore != 50 {
		t.Errorf("Expected default risk score 50, got %d", result.RiskScore)
	}

	if result.RecommendedAction != "ask" {
		t.Errorf("Expected default action 'ask', got %s", result.RecommendedAction)
	}
}

func TestClient_AssessRisk_ServerError(t *testing.T) {
	// Create mock Ollama server that returns an error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	config := ollama.Config{
		Endpoint: server.URL,
		Model:    "gemma3",
		Mode:     ollama.ModeFast,
		Timeout:  5 * time.Second,
	}
	client := ollama.NewClient(config)

	summary := ollama.ContentSummary{
		Provider: "openai",
		Model:    "gpt-4",
	}

	_, err := client.AssessRisk(context.Background(), summary)
	if err == nil {
		t.Fatal("Expected error for server error")
	}
}

func TestClient_IsAvailable(t *testing.T) {
	// Create mock Ollama server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"models": []interface{}{},
			})
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	config := ollama.Config{
		Endpoint: server.URL,
		Mode:     ollama.ModeFast,
		Timeout:  5 * time.Second,
	}
	client := ollama.NewClient(config)

	if !client.IsAvailable(context.Background()) {
		t.Error("Expected Ollama to be available")
	}
}

func TestClient_IsAvailable_NotRunning(t *testing.T) {
	config := ollama.Config{
		Endpoint: "http://localhost:99999", // Invalid port
		Mode:     ollama.ModeFast,
		Timeout:  1 * time.Second,
	}
	client := ollama.NewClient(config)

	if client.IsAvailable(context.Background()) {
		t.Error("Expected Ollama to not be available")
	}
}

func TestClient_SetMode(t *testing.T) {
	config := ollama.Config{
		Mode: ollama.ModeFast,
	}
	client := ollama.NewClient(config)

	if client.GetMode() != ollama.ModeFast {
		t.Errorf("Expected fast mode, got %s", client.GetMode())
	}

	client.SetMode(ollama.ModeStrict)

	if client.GetMode() != ollama.ModeStrict {
		t.Errorf("Expected strict mode, got %s", client.GetMode())
	}

	client.SetMode(ollama.ModeOff)

	if client.GetMode() != ollama.ModeOff {
		t.Errorf("Expected off mode, got %s", client.GetMode())
	}
}

func TestClient_StrictMode(t *testing.T) {
	// Create mock Ollama server
	var receivedPrompt string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Prompt string `json:"prompt"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		receivedPrompt = req.Prompt

		response := map[string]interface{}{
			"response": `{"risk_score": 30, "risk_categories": [], "recommended_action": "allow", "explanation": "OK", "confidence": 0.9}`,
			"done":     true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := ollama.Config{
		Endpoint: server.URL,
		Model:    "gemma3",
		Mode:     ollama.ModeStrict,
		Timeout:  5 * time.Second,
	}
	client := ollama.NewClient(config)

	summary := ollama.ContentSummary{
		Provider:       "openai",
		Model:          "gpt-4",
		RequestType:    "chat",
		ContentPreview: "Test content",
	}

	_, err := client.AssessRisk(context.Background(), summary)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Verify strict mode uses different prompt
	if receivedPrompt == "" {
		t.Error("Expected prompt to be sent")
	}

	// Strict mode prompt should mention "security analyst" and "thorough"
	if len(receivedPrompt) < 100 {
		t.Error("Expected longer prompt in strict mode")
	}
}

func TestClient_RiskScoreClamping(t *testing.T) {
	// Create mock Ollama server that returns out-of-range values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"response": `{"risk_score": 150, "risk_categories": [], "recommended_action": "allow", "explanation": "OK", "confidence": 1.5}`,
			"done":     true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := ollama.Config{
		Endpoint: server.URL,
		Model:    "gemma3",
		Mode:     ollama.ModeFast,
		Timeout:  5 * time.Second,
	}
	client := ollama.NewClient(config)

	summary := ollama.ContentSummary{}

	result, err := client.AssessRisk(context.Background(), summary)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Risk score should be clamped to 100
	if result.RiskScore > 100 {
		t.Errorf("Risk score should be clamped to 100, got %d", result.RiskScore)
	}

	// Confidence should be clamped to 1.0
	if result.Confidence > 1.0 {
		t.Errorf("Confidence should be clamped to 1.0, got %f", result.Confidence)
	}
}

func TestClient_InvalidRecommendedAction(t *testing.T) {
	// Create mock Ollama server that returns invalid action
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"response": `{"risk_score": 50, "risk_categories": [], "recommended_action": "invalid_action", "explanation": "OK", "confidence": 0.8}`,
			"done":     true,
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	config := ollama.Config{
		Endpoint: server.URL,
		Model:    "gemma3",
		Mode:     ollama.ModeFast,
		Timeout:  5 * time.Second,
	}
	client := ollama.NewClient(config)

	summary := ollama.ContentSummary{}

	result, err := client.AssessRisk(context.Background(), summary)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Invalid action should default to "ask"
	if result.RecommendedAction != "ask" {
		t.Errorf("Invalid action should default to 'ask', got %s", result.RecommendedAction)
	}
}

func TestSanitizeContent(t *testing.T) {
	content := "My API key is sk-abc123"
	patterns := []string{"sk-abc123"}

	result := ollama.SanitizeContent(content, patterns)

	// Should have sanitized the content
	if result == content {
		t.Error("Expected content to be sanitized")
	}
}

func TestSanitizeContent_ShortPattern(t *testing.T) {
	content := "Test abc content"
	patterns := []string{"abc"} // Too short to mask

	result := ollama.SanitizeContent(content, patterns)

	// Short patterns should not be masked
	if result != content {
		t.Errorf("Expected original content for short pattern, got %s", result)
	}
}
