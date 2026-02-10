package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/brad07/ninjashield/pkg/scanners"
)

func TestHTTPScannerConfig(t *testing.T) {
	cfg := DefaultHTTPScannerConfig()

	if cfg.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", cfg.Timeout)
	}
	if cfg.HealthEndpoint != "/health" {
		t.Errorf("Expected health endpoint /health, got %s", cfg.HealthEndpoint)
	}
	if cfg.ScanEndpoint != "/scan" {
		t.Errorf("Expected scan endpoint /scan, got %s", cfg.ScanEndpoint)
	}
	if cfg.Priority != 50 {
		t.Errorf("Expected priority 50, got %d", cfg.Priority)
	}
}

func TestHTTPProviderConfig(t *testing.T) {
	cfg := DefaultHTTPProviderConfig()

	if cfg.Timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", cfg.Timeout)
	}
	if cfg.HealthEndpoint != "/health" {
		t.Errorf("Expected health endpoint /health, got %s", cfg.HealthEndpoint)
	}
	if cfg.AssessCommandEndpoint != "/assess/command" {
		t.Errorf("Expected assess command endpoint /assess/command, got %s", cfg.AssessCommandEndpoint)
	}
}

func TestHTTPScannerWithMockServer(t *testing.T) {
	// Create a mock HTTP scanner server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/scan":
			resp := HTTPScanResponse{
				RequestID: "test-req",
				Findings: []scanners.Finding{
					{Type: "test", Category: "test", Severity: "low", Message: "Test finding"},
				},
				RiskScore:        25,
				ProcessingTimeMs: 10,
			}
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create scanner with mock server URL
	config := HTTPScannerConfig{
		URL:            server.URL,
		Timeout:        5 * time.Second,
		HealthEndpoint: "/health",
		ScanEndpoint:   "/scan",
		Priority:       100,
	}

	scanner := NewHTTPScanner("test", "Test HTTP Scanner", config)

	// Verify info
	info := scanner.Info()
	if info.ID != "scanner:test" {
		t.Errorf("Expected ID 'scanner:test', got %s", info.ID)
	}
	if info.Tier != TierHTTP {
		t.Errorf("Expected tier HTTP, got %s", info.Tier)
	}

	ctx := context.Background()

	// Initialize
	if err := scanner.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Health check
	if err := scanner.HealthCheck(ctx); err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	// Scan
	req := &ScanRequest{
		ID:          "test-req",
		Content:     "echo hello",
		ContentType: "command",
	}

	resp, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if resp.RequestID != "test-req" {
		t.Errorf("Expected request ID 'test-req', got %s", resp.RequestID)
	}
	if len(resp.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(resp.Findings))
	}
	if resp.RiskScore != 25 {
		t.Errorf("Expected risk score 25, got %d", resp.RiskScore)
	}

	// Shutdown
	if err := scanner.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
}

func TestHTTPProviderWithMockServer(t *testing.T) {
	// Create a mock HTTP provider server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/assess/command":
			resp := HTTPAssessmentResponse{
				RiskScore:      50,
				Confidence:     0.85,
				Recommendation: RecommendationAsk,
				Reasoning:      "Moderate risk command",
				RiskFactors:    []string{"network access"},
			}
			json.NewEncoder(w).Encode(resp)
		case "/assess/content":
			resp := HTTPAssessmentResponse{
				RiskScore:      30,
				Confidence:     0.9,
				Recommendation: RecommendationAllow,
				Reasoning:      "Low risk content",
			}
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create provider with mock server URL
	config := HTTPProviderConfig{
		URL:                   server.URL,
		Timeout:               5 * time.Second,
		HealthEndpoint:        "/health",
		AssessCommandEndpoint: "/assess/command",
		AssessContentEndpoint: "/assess/content",
	}

	provider := NewHTTPProvider("test", "Test HTTP Provider", config)

	// Verify info
	info := provider.Info()
	if info.ID != "llm:test" {
		t.Errorf("Expected ID 'llm:test', got %s", info.ID)
	}
	if info.Tier != TierHTTP {
		t.Errorf("Expected tier HTTP, got %s", info.Tier)
	}

	ctx := context.Background()

	// Initialize
	if err := provider.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Check availability
	if !provider.IsAvailable(ctx) {
		t.Error("Expected provider to be available")
	}

	// Assess command
	cmdReq := &CommandAssessmentRequest{
		ID:      "test-cmd",
		Command: "curl http://example.com",
	}

	assessment, err := provider.AssessCommand(ctx, cmdReq)
	if err != nil {
		t.Fatalf("AssessCommand failed: %v", err)
	}

	if assessment.Score != 50 {
		t.Errorf("Expected score 50, got %d", assessment.Score)
	}
	if assessment.Recommendation != RecommendationAsk {
		t.Errorf("Expected recommendation ASK, got %s", assessment.Recommendation)
	}

	// Assess content
	contentReq := &ContentAssessmentRequest{
		ID:          "test-content",
		Content:     "Hello world",
		ContentType: "message",
	}

	assessment, err = provider.AssessContent(ctx, contentReq)
	if err != nil {
		t.Fatalf("AssessContent failed: %v", err)
	}

	if assessment.Score != 30 {
		t.Errorf("Expected score 30, got %d", assessment.Score)
	}
	if assessment.Recommendation != RecommendationAllow {
		t.Errorf("Expected recommendation ALLOW, got %s", assessment.Recommendation)
	}

	// Check interface methods
	if provider.SupportsStreaming() {
		t.Error("Expected SupportsStreaming to be false")
	}

	modelInfo := provider.ModelInfo()
	if modelInfo.Provider != "http" {
		t.Errorf("Expected provider 'http', got %s", modelInfo.Provider)
	}

	// Shutdown
	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
}

func TestHTTPScannerRetry(t *testing.T) {
	attempts := 0

	// Server that fails twice then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusOK)
		case "/scan":
			attempts++
			if attempts < 3 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			resp := HTTPScanResponse{
				RequestID: "retry-test",
				RiskScore: 10,
			}
			json.NewEncoder(w).Encode(resp)
		}
	}))
	defer server.Close()

	config := HTTPScannerConfig{
		URL:            server.URL,
		Timeout:        1 * time.Second,
		HealthEndpoint: "/health",
		ScanEndpoint:   "/scan",
		RetryCount:     3,
		RetryDelay:     10 * time.Millisecond,
	}

	scanner := NewHTTPScanner("retry-test", "Retry Test", config)
	ctx := context.Background()

	if err := scanner.Init(ctx, nil); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	req := &ScanRequest{ID: "retry-test", Content: "test"}
	resp, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Scan failed after retries: %v", err)
	}

	if resp.RiskScore != 10 {
		t.Errorf("Expected risk score 10, got %d", resp.RiskScore)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestHTTPScannerFactory(t *testing.T) {
	factory := &HTTPScannerFactory{}

	// Test missing URL
	_, err := factory.Create("test", map[string]any{})
	if err == nil {
		t.Error("Expected error for missing URL")
	}

	// Test with valid config
	config := map[string]any{
		"url":      "http://localhost:8080",
		"priority": 100,
		"timeout":  "10s",
	}

	scanner, err := factory.Create("test", config)
	if err != nil {
		t.Fatalf("Factory create failed: %v", err)
	}

	if scanner.Priority() != 100 {
		t.Errorf("Expected priority 100, got %d", scanner.Priority())
	}
}

func TestHTTPProviderFactory(t *testing.T) {
	factory := &HTTPProviderFactory{}

	// Test missing URL
	_, err := factory.Create("test", map[string]any{})
	if err == nil {
		t.Error("Expected error for missing URL")
	}

	// Test with valid config
	config := map[string]any{
		"url":     "http://localhost:8080",
		"api_key": "test-key",
	}

	provider, err := factory.Create("test", config)
	if err != nil {
		t.Fatalf("Factory create failed: %v", err)
	}

	info := provider.Info()
	if info.ID != "llm:test" {
		t.Errorf("Expected ID 'llm:test', got %s", info.ID)
	}
}
