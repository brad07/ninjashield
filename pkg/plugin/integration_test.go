package plugin

import (
	"context"
	"encoding/json"
	"testing"
)

func TestBaseIntegration(t *testing.T) {
	base := NewBaseIntegration("test", "Test Integration", IntegrationTypeCLIHook)

	// Verify info
	info := base.Info()
	if info.ID != "integration:test" {
		t.Errorf("Expected ID 'integration:test', got %s", info.ID)
	}
	if info.Type != PluginTypeIntegration {
		t.Errorf("Expected type integration, got %s", info.Type)
	}

	ctx := context.Background()

	// Test Init
	config := map[string]any{
		"risk_tolerance": "strict",
		"allowed_tools":  []string{"ls", "cat"},
		"blocked_tools":  []string{"rm", "sudo"},
	}

	if err := base.Init(ctx, config); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	// Verify config was parsed
	cfg := base.Config()
	if cfg.RiskTolerance != "strict" {
		t.Errorf("Expected risk tolerance 'strict', got %s", cfg.RiskTolerance)
	}

	// Test tool lists
	if !base.IsToolAllowed("ls") {
		t.Error("Expected 'ls' to be allowed")
	}
	if !base.IsToolBlocked("rm") {
		t.Error("Expected 'rm' to be blocked")
	}
	if base.IsToolAllowed("vim") {
		t.Error("Expected 'vim' to not be in allowed list")
	}

	// Test health check
	if err := base.HealthCheck(ctx); err != nil {
		t.Fatalf("Health check failed: %v", err)
	}

	// Test shutdown
	if err := base.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}

	// Health check should fail after shutdown
	if err := base.HealthCheck(ctx); err == nil {
		t.Error("Expected health check to fail after shutdown")
	}
}

func TestIntegrationRequest(t *testing.T) {
	req := &IntegrationRequest{
		ID:            "test-123",
		IntegrationID: "claude-code",
		RequestType:   "command",
		Payload: IntegrationPayload{
			ToolName:    "Bash",
			Command:     "echo hello",
			ContentType: "shell_command",
		},
		Context: IntegrationContext{
			User:             "testuser",
			WorkingDirectory: "/home/testuser",
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal request: %v", err)
	}

	var decoded IntegrationRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal request: %v", err)
	}

	if decoded.ID != req.ID {
		t.Errorf("Expected ID %s, got %s", req.ID, decoded.ID)
	}
	if decoded.Payload.Command != req.Payload.Command {
		t.Errorf("Expected command %s, got %s", req.Payload.Command, decoded.Payload.Command)
	}
}

func TestIntegrationResponse(t *testing.T) {
	resp := &IntegrationResponse{
		RequestID: "test-123",
		Allowed:   false,
		Decision:  "deny",
		RiskScore: 85,
		Reason:    "Dangerous command detected",
		Findings: []IntegrationFinding{
			{Type: "dangerous_pattern", Category: "security", Severity: "high", Message: "rm -rf detected"},
		},
	}

	// Test JSON marshaling
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var decoded IntegrationResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if decoded.Allowed != resp.Allowed {
		t.Errorf("Expected allowed %v, got %v", resp.Allowed, decoded.Allowed)
	}
	if decoded.RiskScore != resp.RiskScore {
		t.Errorf("Expected risk score %d, got %d", resp.RiskScore, decoded.RiskScore)
	}
	if len(decoded.Findings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(decoded.Findings))
	}
}

func TestIntegrationConfig(t *testing.T) {
	cfg := IntegrationConfig{
		ID:            "test",
		Name:          "Test Integration",
		Enabled:       true,
		Type:          IntegrationTypeWebhook,
		RiskTolerance: "balanced",
		WebhookPath:   "/webhook/test",
		WebhookSecret: "secret123",
		AllowedTools:  []string{"safe-tool"},
		BlockedTools:  []string{"dangerous-tool"},
	}

	// Test JSON marshaling
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	var decoded IntegrationConfig
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if decoded.WebhookPath != cfg.WebhookPath {
		t.Errorf("Expected webhook path %s, got %s", cfg.WebhookPath, decoded.WebhookPath)
	}
}

func TestConvertFindingsToIntegration(t *testing.T) {
	findings := []Finding{
		{Type: "secret", Category: "credentials", Severity: "critical", Message: "API key found", Confidence: 0.95},
		{Type: "pii", Category: "personal_data", Severity: "high", Message: "Email detected", Confidence: 0.85},
	}

	converted := ConvertFindingsToIntegration(findings)

	if len(converted) != 2 {
		t.Fatalf("Expected 2 findings, got %d", len(converted))
	}

	if converted[0].Type != "secret" {
		t.Errorf("Expected type 'secret', got %s", converted[0].Type)
	}
	if converted[1].Severity != "high" {
		t.Errorf("Expected severity 'high', got %s", converted[1].Severity)
	}
}

func TestIntegrationTypes(t *testing.T) {
	types := []IntegrationType{
		IntegrationTypeCLIHook,
		IntegrationTypeWebhook,
		IntegrationTypeIDE,
		IntegrationTypeAPI,
	}

	for _, typ := range types {
		if typ == "" {
			t.Error("Integration type should not be empty")
		}
	}

	if IntegrationTypeCLIHook != "cli_hook" {
		t.Errorf("Expected cli_hook, got %s", IntegrationTypeCLIHook)
	}
	if IntegrationTypeWebhook != "webhook" {
		t.Errorf("Expected webhook, got %s", IntegrationTypeWebhook)
	}
}
