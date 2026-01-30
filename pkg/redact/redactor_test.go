package redact_test

import (
	"testing"

	"github.com/brad07/ninjashield/pkg/redact"
)

func TestRedactor_NewRedactor(t *testing.T) {
	r := redact.NewRedactor()
	if r == nil {
		t.Fatal("Expected redactor to be created")
	}

	patterns := r.GetPatterns()
	if len(patterns) == 0 {
		t.Error("Expected default patterns to be registered")
	}
}

func TestRedactor_RedactOpenAIKey(t *testing.T) {
	r := redact.NewRedactor()

	content := "My API key is sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if result.Redacted == content {
		t.Error("Expected content to be redacted")
	}

	if len(result.Replacements) != 1 {
		t.Errorf("Expected 1 replacement, got %d", len(result.Replacements))
	}

	if result.Replacements[0].Category != "secrets" {
		t.Errorf("Expected category 'secrets', got %s", result.Replacements[0].Category)
	}
}

func TestRedactor_RedactAnthropicKey(t *testing.T) {
	r := redact.NewRedactor()

	content := "Using sk-ant-api03-abc123def456ghi789jkl012mno345pqr"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[ANTHROPIC_KEY_REDACTED]") {
		t.Error("Expected Anthropic key to be redacted")
	}
}

func TestRedactor_RedactAWSKey(t *testing.T) {
	r := redact.NewRedactor()

	content := "AWS key: AKIAIOSFODNN7EXAMPLE"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[AWS_KEY_REDACTED]") {
		t.Error("Expected AWS key to be redacted")
	}
}

func TestRedactor_RedactGitHubToken(t *testing.T) {
	r := redact.NewRedactor()

	content := "Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[GITHUB_TOKEN_REDACTED]") {
		t.Error("Expected GitHub token to be redacted")
	}
}

func TestRedactor_RedactJWT(t *testing.T) {
	r := redact.NewRedactor()

	// Test JWT without Bearer prefix to specifically test JWT pattern
	content := "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[JWT_REDACTED]") {
		t.Error("Expected JWT to be redacted")
	}
}

func TestRedactor_RedactBearerToken(t *testing.T) {
	r := redact.NewRedactor()

	// Bearer tokens (including JWTs) should be redacted
	content := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	// Either JWT or Bearer pattern can match - both are valid redactions
	if !contains(result.Redacted, "[JWT_REDACTED]") && !contains(result.Redacted, "[BEARER_TOKEN_REDACTED]") {
		t.Errorf("Expected token to be redacted, got: %s", result.Redacted)
	}
}

func TestRedactor_RedactSSN(t *testing.T) {
	r := redact.NewRedactor()

	content := "My SSN is 123-45-6789"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[SSN_REDACTED]") {
		t.Error("Expected SSN to be redacted")
	}

	if result.Replacements[0].Category != "pii" {
		t.Errorf("Expected category 'pii', got %s", result.Replacements[0].Category)
	}
}

func TestRedactor_RedactEmail(t *testing.T) {
	r := redact.NewRedactor()

	content := "Contact me at john.doe@example.com"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[EMAIL_REDACTED]") {
		t.Error("Expected email to be redacted")
	}
}

func TestRedactor_RedactPhone(t *testing.T) {
	r := redact.NewRedactor()

	content := "Call me at (555) 123-4567"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[PHONE_REDACTED]") {
		t.Error("Expected phone to be redacted")
	}
}

func TestRedactor_RedactCreditCard(t *testing.T) {
	r := redact.NewRedactor()

	content := "Card: 4111-1111-1111-1111"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[CREDIT_CARD_REDACTED]") {
		t.Error("Expected credit card to be redacted")
	}
}

func TestRedactor_RedactPrivateKey(t *testing.T) {
	r := redact.NewRedactor()

	content := `Here is my key:
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
Don't share it!`
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[PRIVATE_KEY_REDACTED]") {
		t.Error("Expected private key to be redacted")
	}
}

func TestRedactor_RedactSecretsOnly(t *testing.T) {
	r := redact.NewRedactor()

	content := "Key: sk-abc123def456ghi789jkl012mno345pqr, Email: test@example.com"
	result := r.RedactSecrets(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	// Should redact the key but not the email
	if !contains(result.Redacted, "[OPENAI_KEY_REDACTED]") {
		t.Error("Expected API key to be redacted")
	}

	if contains(result.Redacted, "[EMAIL_REDACTED]") {
		t.Error("Expected email to NOT be redacted when only redacting secrets")
	}

	if !contains(result.Redacted, "test@example.com") {
		t.Error("Expected email to remain in content")
	}
}

func TestRedactor_RedactPIIOnly(t *testing.T) {
	r := redact.NewRedactor()

	content := "Key: sk-abc123def456ghi789jkl012mno345pqr, SSN: 123-45-6789"
	result := r.RedactPII(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	// Should redact SSN but not the key
	if !contains(result.Redacted, "[SSN_REDACTED]") {
		t.Error("Expected SSN to be redacted")
	}

	if contains(result.Redacted, "[OPENAI_KEY_REDACTED]") {
		t.Error("Expected API key to NOT be redacted when only redacting PII")
	}
}

func TestRedactor_ContainsSecrets(t *testing.T) {
	r := redact.NewRedactor()

	if !r.ContainsSecrets("Key: sk-abc123def456ghi789jkl012mno345pqr") {
		t.Error("Expected to detect secret")
	}

	if r.ContainsSecrets("No secrets here") {
		t.Error("Expected to not detect secret")
	}
}

func TestRedactor_ContainsPII(t *testing.T) {
	r := redact.NewRedactor()

	if !r.ContainsPII("SSN: 123-45-6789") {
		t.Error("Expected to detect PII")
	}

	if r.ContainsPII("No PII here") {
		t.Error("Expected to not detect PII")
	}
}

func TestRedactor_NoChanges(t *testing.T) {
	r := redact.NewRedactor()

	content := "This is just normal text with no secrets or PII."
	result := r.Redact(content)

	if result.HasChanges {
		t.Error("Expected no changes to be made")
	}

	if result.Redacted != content {
		t.Error("Expected content to remain unchanged")
	}

	if len(result.Replacements) != 0 {
		t.Errorf("Expected 0 replacements, got %d", len(result.Replacements))
	}
}

func TestRedactor_MultipleMatches(t *testing.T) {
	r := redact.NewRedactor()

	content := "Keys: sk-key1abcdefghijklmnopqrstuvwxyz and sk-key2abcdefghijklmnopqrstuvwxyz"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	// Count how many redactions
	replacementCount := 0
	for _, repl := range result.Replacements {
		if repl.PatternName == "openai_api_key" {
			replacementCount++
		}
	}

	if replacementCount < 2 {
		t.Errorf("Expected at least 2 OpenAI key redactions, got %d", replacementCount)
	}
}

func TestRedactor_AddCustomPattern(t *testing.T) {
	r := redact.NewRedactor()

	err := r.AddPattern("custom_id", `CUST-[0-9]{6}`, "[CUSTOMER_ID_REDACTED]", "custom")
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}

	content := "Customer ID: CUST-123456"
	result := r.Redact(content)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Redacted, "[CUSTOMER_ID_REDACTED]") {
		t.Error("Expected custom pattern to be applied")
	}
}

func TestRedactor_RemovePattern(t *testing.T) {
	r := redact.NewRedactor()

	// Remove email pattern
	r.RemovePattern("email")

	content := "Email: test@example.com"
	result := r.Redact(content)

	// Email should not be redacted anymore
	if contains(result.Redacted, "[EMAIL_REDACTED]") {
		t.Error("Expected email pattern to be removed")
	}
}

func TestTransformer_Transform(t *testing.T) {
	tr := redact.NewTransformer()

	content := "Key: sk-abc123def456ghi789jkl012mno345pqr, SSN: 123-45-6789"
	opts := redact.TransformOptions{
		RedactSecrets: true,
		RedactPII:     true,
	}

	result := tr.Transform(content, opts)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if !contains(result.Transformed, "[OPENAI_KEY_REDACTED]") {
		t.Error("Expected API key to be redacted")
	}

	if !contains(result.Transformed, "[SSN_REDACTED]") {
		t.Error("Expected SSN to be redacted")
	}
}

func TestTransformer_CustomReplacements(t *testing.T) {
	tr := redact.NewTransformer()

	content := "The company name is ACME Corp and contact is ACME Support"
	opts := redact.TransformOptions{
		CustomReplacements: []redact.CustomReplacement{
			{Find: "ACME", Replace: "[COMPANY]"},
		},
	}

	result := tr.Transform(content, opts)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if contains(result.Transformed, "ACME") {
		t.Error("Expected ACME to be replaced")
	}

	if !contains(result.Transformed, "[COMPANY]") {
		t.Error("Expected [COMPANY] replacement")
	}
}

func TestTransformer_RemovePatterns(t *testing.T) {
	tr := redact.NewTransformer()

	content := "Remove DEBUG: some debug info here and continue"
	opts := redact.TransformOptions{
		RemovePatterns: []string{`DEBUG:\s*[^\n]+`},
	}

	result := tr.Transform(content, opts)

	if !result.HasChanges {
		t.Error("Expected changes to be made")
	}

	if contains(result.Transformed, "DEBUG:") {
		t.Error("Expected DEBUG line to be removed")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
