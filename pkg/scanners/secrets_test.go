package scanners

import (
	"testing"
)

func TestSecretsScanner_Name(t *testing.T) {
	s := NewSecretsScanner()
	if s.Name() != "secrets" {
		t.Errorf("Name() = %v, want secrets", s.Name())
	}
}

func TestSecretsScanner_AWSKeys(t *testing.T) {
	s := NewSecretsScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
		keyType string
	}{
		{
			name:    "AWS access key",
			input:   "AKIAIOSFODNN7EXAMPLE",
			wantHit: true,
			keyType: "aws_access_key",
		},
		{
			name:    "AWS access key in context",
			input:   "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
			wantHit: true,
			keyType: "aws_access_key",
		},
		{
			name:    "AWS secret key",
			input:   "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			wantHit: true,
			keyType: "aws_secret_key",
		},
		{
			name:    "Not an AWS key",
			input:   "AKIA is a prefix but this is not a key",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if tt.keyType == "" || f.Type == tt.keyType {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestSecretsScanner_GitHubTokens(t *testing.T) {
	s := NewSecretsScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "GitHub PAT",
			input:   "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantHit: true,
		},
		{
			name:    "GitHub OAuth",
			input:   "gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantHit: true,
		},
		{
			name:    "GitHub App",
			input:   "ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantHit: true,
		},
		{
			name:    "GitHub Refresh",
			input:   "ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantHit: true,
		},
		{
			name:    "Not a GitHub token",
			input:   "ghp_short",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := len(findings) > 0
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestSecretsScanner_AnthropicKey(t *testing.T) {
	s := NewSecretsScanner()

	input := "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	findings := s.Scan(input)

	found := false
	for _, f := range findings {
		if f.Type == "anthropic_api_key" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find Anthropic API key")
	}
}

func TestSecretsScanner_PrivateKeys(t *testing.T) {
	s := NewSecretsScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "RSA private key",
			input:   "-----BEGIN RSA PRIVATE KEY-----\nMIIEp...",
			wantHit: true,
		},
		{
			name:    "OpenSSH private key",
			input:   "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz...",
			wantHit: true,
		},
		{
			name:    "EC private key",
			input:   "-----BEGIN EC PRIVATE KEY-----\nMHQC...",
			wantHit: true,
		},
		{
			name:    "PGP private key",
			input:   "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion...",
			wantHit: true,
		},
		{
			name:    "Public key (should not match)",
			input:   "-----BEGIN PUBLIC KEY-----\nMIIB...",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := len(findings) > 0
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestSecretsScanner_DatabaseURIs(t *testing.T) {
	s := NewSecretsScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "PostgreSQL URI with credentials",
			input:   "postgresql://user:password@localhost:5432/db",
			wantHit: true,
		},
		{
			name:    "MySQL URI with credentials",
			input:   "mysql://root:secret@127.0.0.1/mydb",
			wantHit: true,
		},
		{
			name:    "MongoDB URI with credentials",
			input:   "mongodb://user:pass@cluster.mongodb.net/db",
			wantHit: true,
		},
		{
			name:    "MongoDB SRV URI",
			input:   "mongodb+srv://user:pass@cluster.mongodb.net",
			wantHit: true,
		},
		{
			name:    "Redis URI with credentials",
			input:   "redis://user:password@localhost:6379",
			wantHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := len(findings) > 0
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v, findings: %v", found, tt.wantHit, findings)
			}
		})
	}
}

func TestSecretsScanner_JWT(t *testing.T) {
	s := NewSecretsScanner()

	// Example JWT (not a real secret, just structure)
	input := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	findings := s.Scan(input)

	found := false
	for _, f := range findings {
		if f.Type == "jwt_token" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find JWT token")
	}
}

func TestSecretsScanner_Stripe(t *testing.T) {
	s := NewSecretsScanner()

	tests := []struct {
		name     string
		input    string
		keyType  string
		severity string
	}{
		{
			name:     "Stripe secret key",
			input:    "sk_test_FAKE00000000000000000000000000",
			keyType:  "stripe_secret_key",
			severity: "critical",
		},
		{
			name:     "Stripe publishable key",
			input:    "pk_test_FAKE00000000000000000000000000",
			keyType:  "stripe_publishable_key",
			severity: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Type == tt.keyType {
					found = true
					if f.Severity != tt.severity {
						t.Errorf("Severity = %v, want %v", f.Severity, tt.severity)
					}
					break
				}
			}
			if !found {
				t.Errorf("Expected to find %s", tt.keyType)
			}
		})
	}
}

func TestSecretsScanner_NoFalsePositives(t *testing.T) {
	s := NewSecretsScanner()

	// These should NOT trigger secrets detection
	inputs := []string{
		"Hello world",
		"const foo = 'bar'",
		"https://example.com",
		"user@example.com",
		"SELECT * FROM users",
		"function test() { return true; }",
	}

	for _, input := range inputs {
		t.Run(input[:min(20, len(input))], func(t *testing.T) {
			findings := s.Scan(input)
			// Filter out low-confidence findings
			highConfidence := 0
			for _, f := range findings {
				if f.Confidence >= 0.7 {
					highConfidence++
				}
			}
			if highConfidence > 0 {
				t.Errorf("False positive detected in: %s, findings: %v", input, findings)
			}
		})
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		input    string
		minValue float64
		maxValue float64
	}{
		{"aaaaaaaaaa", 0, 0.1},       // Very low entropy
		{"abcdefghij", 3.0, 4.0},     // Medium entropy
		{"aB3$xY9!mN", 3.0, 4.0},     // Higher entropy
		{"", 0, 0},                    // Empty string
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			entropy := calculateEntropy(tt.input)
			if entropy < tt.minValue || entropy > tt.maxValue {
				t.Errorf("calculateEntropy(%q) = %v, want between %v and %v", tt.input, entropy, tt.minValue, tt.maxValue)
			}
		})
	}
}

func TestRedactSecret(t *testing.T) {
	tests := []struct {
		input     string
		keepChars int
		want      string
	}{
		{"sk-ant-api03-abc123xyz789", 4, "sk-a****************9789"},
		{"short", 4, "*****"},
		{"ab", 4, "**"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := RedactSecret(tt.input, tt.keepChars)
			if len(got) != len(tt.input) {
				t.Errorf("RedactSecret() length = %v, want %v", len(got), len(tt.input))
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
