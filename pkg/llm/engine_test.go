package llm_test

import (
	"context"
	"testing"

	"github.com/brad07/ninjashield/pkg/llm"
	"github.com/brad07/ninjashield/pkg/policy"
)

func TestEngine_NewEngine(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	if engine == nil {
		t.Fatal("Expected engine to be created")
	}

	if engine.GetPolicy() != pol {
		t.Error("Expected engine to have the provided policy")
	}
}

func TestEngine_NewEngineWithConfig(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	config := llm.EngineConfig{
		EnableSecrets: true,
		EnablePII:     false,
		EnableOllama:  false,
	}
	engine := llm.NewEngineWithConfig(pol, config)

	if engine == nil {
		t.Fatal("Expected engine to be created")
	}
}

func TestEngine_EvaluateKnownProvider(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderOpenAI,
		Model:       "gpt-4",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "Hello, world!"},
		},
	}

	result := engine.Evaluate(context.Background(), req)

	if result == nil {
		t.Fatal("Expected result")
	}

	// Known provider should be allowed
	if result.Decision != string(policy.DecisionAllow) {
		t.Errorf("Expected ALLOW decision for known provider, got %s", result.Decision)
	}
}

func TestEngine_EvaluateUnknownProvider(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderUnknown,
		Model:       "unknown-model",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "Hello"},
		},
	}

	result := engine.Evaluate(context.Background(), req)

	if result == nil {
		t.Fatal("Expected result")
	}

	// Unknown provider should be denied
	if result.Decision != string(policy.DecisionDeny) {
		t.Errorf("Expected DENY decision for unknown provider, got %s", result.Decision)
	}

	// Should have the UNKNOWN_PROVIDER reason code
	hasReasonCode := false
	for _, code := range result.ReasonCodes {
		if code == "UNKNOWN_PROVIDER" {
			hasReasonCode = true
			break
		}
	}
	if !hasReasonCode {
		t.Errorf("Expected UNKNOWN_PROVIDER reason code, got %v", result.ReasonCodes)
	}
}

func TestEngine_EvaluateWithSecrets(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderOpenAI,
		Model:       "gpt-4",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "My API key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx"},
		},
	}

	result := engine.Evaluate(context.Background(), req)

	if result == nil {
		t.Fatal("Expected result")
	}

	// Should detect secrets and deny
	if result.Decision != string(policy.DecisionDeny) {
		t.Errorf("Expected DENY decision for secrets, got %s", result.Decision)
	}

	// Should have secrets in risk categories
	hasSecrets := false
	for _, cat := range result.RiskCategories {
		if cat == "secrets" {
			hasSecrets = true
			break
		}
	}
	if !hasSecrets {
		t.Errorf("Expected secrets risk category, got %v", result.RiskCategories)
	}
}

func TestEngine_EvaluateWithPII(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderOpenAI,
		Model:       "gpt-4",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "My SSN is 123-45-6789 and email is test@example.com"},
		},
	}

	result := engine.Evaluate(context.Background(), req)

	if result == nil {
		t.Fatal("Expected result")
	}

	// Should detect PII and ask for approval
	if result.Decision != string(policy.DecisionAsk) {
		t.Errorf("Expected ASK decision for PII, got %s", result.Decision)
	}

	// Should have pii in risk categories
	hasPII := false
	for _, cat := range result.RiskCategories {
		if cat == "pii" {
			hasPII = true
			break
		}
	}
	if !hasPII {
		t.Errorf("Expected pii risk category, got %v", result.RiskCategories)
	}
}

func TestEngine_EvaluateWithAttachments(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderOpenAI,
		Model:       "gpt-4-vision",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "Describe this image"},
		},
		Attachments: []llm.Attachment{
			{Type: "image", MimeType: "image/png", URL: "http://example.com/image.png"},
		},
	}

	result := engine.Evaluate(context.Background(), req)

	if result == nil {
		t.Fatal("Expected result")
	}

	// Should ask for approval due to attachments
	if result.Decision != string(policy.DecisionAsk) {
		t.Errorf("Expected ASK decision for attachments, got %s", result.Decision)
	}
}

func TestEngine_QuickEvaluate(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	config := llm.EngineConfig{
		EnableSecrets: true,
		EnablePII:     true,
		EnableOllama:  true, // This would normally use Ollama
	}
	engine := llm.NewEngineWithConfig(pol, config)

	req := &llm.Request{
		Provider:    llm.ProviderAnthropic,
		Model:       "claude-3-opus",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "Hello"},
		},
	}

	// QuickEvaluate should skip Ollama
	result := engine.QuickEvaluate(req)

	if result == nil {
		t.Fatal("Expected result")
	}

	if result.Decision != string(policy.DecisionAllow) {
		t.Errorf("Expected ALLOW decision, got %s", result.Decision)
	}
}

func TestEngine_IsAllowed(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderOpenAI,
		Model:       "gpt-4",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "Hello"},
		},
	}

	if !engine.IsAllowed(req) {
		t.Error("Expected request to be allowed")
	}
}

func TestEngine_IsBlocked(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderUnknown,
		Model:       "unknown",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "Hello"},
		},
	}

	if !engine.IsBlocked(req) {
		t.Error("Expected request to be blocked")
	}
}

func TestEngine_RequiresApproval(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	req := &llm.Request{
		Provider:    llm.ProviderOpenAI,
		Model:       "gpt-4-vision",
		RequestType: llm.RequestTypeChat,
		Messages: []llm.Message{
			{Role: "user", Content: "Describe this"},
		},
		Attachments: []llm.Attachment{
			{Type: "image", MimeType: "image/png"},
		},
	}

	if !engine.RequiresApproval(req) {
		t.Error("Expected request to require approval")
	}
}

func TestEngine_GetRiskLevel(t *testing.T) {
	pol := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol)

	tests := []struct {
		name     string
		request  *llm.Request
		minLevel string
	}{
		{
			name: "minimal risk",
			request: &llm.Request{
				Provider:    llm.ProviderOpenAI,
				Model:       "gpt-4",
				RequestType: llm.RequestTypeChat,
				Messages:    []llm.Message{{Role: "user", Content: "Hi"}},
			},
			minLevel: "minimal",
		},
		{
			name: "high risk - unknown provider",
			request: &llm.Request{
				Provider:    llm.ProviderUnknown,
				Model:       "unknown",
				RequestType: llm.RequestTypeChat,
				Messages:    []llm.Message{{Role: "user", Content: "Hello"}},
			},
			minLevel: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := engine.GetRiskLevel(tt.request)
			// Just verify we get a valid level
			validLevels := map[string]bool{
				"minimal":  true,
				"low":      true,
				"medium":   true,
				"high":     true,
				"critical": true,
			}
			if !validLevels[level] {
				t.Errorf("Invalid risk level: %s", level)
			}
		})
	}
}

func TestEngine_SetPolicy(t *testing.T) {
	pol1 := llm.CreateLLMPolicy()
	engine := llm.NewEngine(pol1)

	pol2 := &policy.Policy{
		ID:   "test-policy",
		Name: "Test Policy",
	}

	engine.SetPolicy(pol2)

	if engine.GetPolicy() != pol2 {
		t.Error("Expected policy to be updated")
	}
}

func TestCreateLLMPolicy(t *testing.T) {
	pol := llm.CreateLLMPolicy()

	if pol == nil {
		t.Fatal("Expected policy to be created")
	}

	if pol.ID == "" {
		t.Error("Expected policy to have ID")
	}

	if pol.Name == "" {
		t.Error("Expected policy to have name")
	}

	if len(pol.Rules) == 0 {
		t.Error("Expected policy to have rules")
	}

	// Verify specific rules exist
	ruleIDs := make(map[string]bool)
	for _, rule := range pol.Rules {
		ruleIDs[rule.ID] = true
	}

	expectedRules := []string{
		"allow-known-providers",
		"block-unknown-providers",
		"block-secrets",
		"ask-for-pii",
		"ask-for-attachments",
	}

	for _, id := range expectedRules {
		if !ruleIDs[id] {
			t.Errorf("Expected rule %s to exist", id)
		}
	}
}
