package plugin

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// MockIntegration is a simple integration for testing.
type MockIntegration struct {
	*BaseIntegration
	parseError  error
	handleError error
	response    *IntegrationResponse
}

func NewMockIntegration() *MockIntegration {
	return &MockIntegration{
		BaseIntegration: NewBaseIntegration("mock", "Mock Integration", IntegrationTypeWebhook),
		response: &IntegrationResponse{
			RequestID: "mock-123",
			Allowed:   true,
			Decision:  "allow",
			RiskScore: 10,
		},
	}
}

func (m *MockIntegration) Type() IntegrationType {
	return IntegrationTypeWebhook
}

func (m *MockIntegration) ParseRequest(ctx context.Context, raw []byte) (*IntegrationRequest, error) {
	if m.parseError != nil {
		return nil, m.parseError
	}
	return &IntegrationRequest{
		ID:            "mock-123",
		IntegrationID: "mock",
		RequestType:   "command",
		Payload: IntegrationPayload{
			Command: "echo hello",
		},
	}, nil
}

func (m *MockIntegration) FormatResponse(ctx context.Context, req *IntegrationRequest, resp *PipelineResponse) (*IntegrationResponse, error) {
	return m.response, nil
}

func (m *MockIntegration) HandleRequest(ctx context.Context, raw []byte) (*IntegrationResponse, error) {
	if m.handleError != nil {
		return nil, m.handleError
	}
	return m.response, nil
}

func (m *MockIntegration) ValidateConfig(config map[string]any) error {
	return nil
}

func (m *MockIntegration) SupportedRequestTypes() []string {
	return []string{"command"}
}

func TestWebhookHandler(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)

	// Register a mock integration
	mockIntegration := NewMockIntegration()
	if err := handler.RegisterIntegration(mockIntegration); err != nil {
		t.Fatalf("Failed to register integration: %v", err)
	}

	// Verify it was registered
	integration, exists := handler.GetIntegration("mock")
	if !exists {
		t.Error("Expected integration to be registered")
	}
	if integration == nil {
		t.Error("Expected non-nil integration")
	}
}

func TestWebhookHandlerHTTP(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)

	mockIntegration := NewMockIntegration()
	handler.RegisterIntegration(mockIntegration)

	// Create test server
	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Test health endpoint
	resp, err := http.Get(server.URL + "/webhooks/health")
	if err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Test webhook endpoint
	payload := []byte(`{"command": "echo hello"}`)
	resp, err = http.Post(server.URL+"/webhooks/mock", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Webhook request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result IntegrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !result.Allowed {
		t.Error("Expected allowed to be true")
	}
}

func TestWebhookHandlerNotFound(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)

	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Test non-existent integration
	resp, err := http.Post(server.URL+"/webhooks/nonexistent", "application/json", bytes.NewReader([]byte("{}")))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestWebhookHandlerMethodNotAllowed(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)

	mockIntegration := NewMockIntegration()
	handler.RegisterIntegration(mockIntegration)

	server := httptest.NewServer(handler.Handler())
	defer server.Close()

	// Test GET instead of POST
	resp, err := http.Get(server.URL + "/webhooks/mock")
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", resp.StatusCode)
	}
}

func TestWebhookSignatureVerification(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)

	secret := "test-secret-123"
	payload := []byte(`{"command": "echo hello"}`)

	// Calculate expected signature
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	// Verify correct signature
	if !handler.verifySignature(payload, expectedSig, secret) {
		t.Error("Expected signature verification to succeed")
	}

	// Verify incorrect signature fails
	if handler.verifySignature(payload, "sha256=invalid", secret) {
		t.Error("Expected invalid signature to fail")
	}

	// Verify empty signature fails
	if handler.verifySignature(payload, "", secret) {
		t.Error("Expected empty signature to fail")
	}
}

func TestWebhookClient(t *testing.T) {
	// Create a test server
	received := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		json.NewDecoder(r.Body).Decode(&payload)
		received <- payload
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := NewWebhookClient(WebhookClientConfig{
		URL:    server.URL,
		Secret: "test-secret",
	})

	ctx := context.Background()
	err := client.Send(ctx, "test_event", map[string]any{"key": "value"})
	if err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	// Check received payload
	payload := <-received
	if payload["event"] != "test_event" {
		t.Errorf("Expected event 'test_event', got %v", payload["event"])
	}
}

func TestIntegrationRouter(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)

	mockIntegration := NewMockIntegration()
	handler.RegisterIntegration(mockIntegration)

	router := NewIntegrationRouter(handler)

	ctx := context.Background()
	resp, err := router.Route(ctx, "mock", []byte(`{}`))
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}

	if resp.RequestID != "mock-123" {
		t.Errorf("Expected request ID 'mock-123', got %s", resp.RequestID)
	}
}

func TestIntegrationRouterNotFound(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)
	router := NewIntegrationRouter(handler)

	ctx := context.Background()
	_, err := router.Route(ctx, "nonexistent", []byte(`{}`))
	if err == nil {
		t.Error("Expected error for non-existent integration")
	}
}

func TestUnregisterIntegration(t *testing.T) {
	handler := NewWebhookHandler(nil, nil)

	mockIntegration := NewMockIntegration()
	handler.RegisterIntegration(mockIntegration)

	// Verify registered
	_, exists := handler.GetIntegration("mock")
	if !exists {
		t.Error("Expected integration to be registered")
	}

	// Unregister
	handler.UnregisterIntegration("mock")

	// Verify unregistered
	_, exists = handler.GetIntegration("mock")
	if exists {
		t.Error("Expected integration to be unregistered")
	}
}
