package scanners

import (
	"math"
	"regexp"
	"strings"
)

// SecretsScanner detects secrets like API keys, tokens, and private keys.
type SecretsScanner struct {
	patterns []secretPattern
}

type secretPattern struct {
	name       string
	regex      *regexp.Regexp
	severity   string
	confidence float64
	message    string
}

// NewSecretsScanner creates a new secrets scanner with default patterns.
func NewSecretsScanner() *SecretsScanner {
	return &SecretsScanner{
		patterns: defaultSecretPatterns(),
	}
}

func defaultSecretPatterns() []secretPattern {
	return []secretPattern{
		// AWS
		{
			name:       "aws_access_key",
			regex:      regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "AWS Access Key ID detected",
		},
		{
			name:       "aws_secret_key",
			regex:      regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			severity:   "critical",
			confidence: 0.90,
			message:    "AWS Secret Access Key detected",
		},

		// GitHub
		{
			name:       "github_token",
			regex:      regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "GitHub Personal Access Token detected",
		},
		{
			name:       "github_oauth",
			regex:      regexp.MustCompile(`\b(gho_[a-zA-Z0-9]{36})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "GitHub OAuth Token detected",
		},
		{
			name:       "github_app",
			regex:      regexp.MustCompile(`\b(ghu_[a-zA-Z0-9]{36})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "GitHub App Token detected",
		},
		{
			name:       "github_refresh",
			regex:      regexp.MustCompile(`\b(ghr_[a-zA-Z0-9]{36})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "GitHub Refresh Token detected",
		},

		// Anthropic
		{
			name:       "anthropic_api_key",
			regex:      regexp.MustCompile(`\b(sk-ant-api[a-zA-Z0-9-]{20,})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "Anthropic API Key detected",
		},

		// OpenAI
		{
			name:       "openai_api_key",
			regex:      regexp.MustCompile(`\b(sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "OpenAI API Key detected",
		},
		{
			name:       "openai_api_key_new",
			regex:      regexp.MustCompile(`\b(sk-proj-[a-zA-Z0-9-_]{40,})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "OpenAI Project API Key detected",
		},

		// Stripe
		{
			name:       "stripe_secret_key",
			regex:      regexp.MustCompile(`\b(sk_live_[a-zA-Z0-9]{24,})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "Stripe Secret Key detected",
		},
		{
			name:       "stripe_publishable_key",
			regex:      regexp.MustCompile(`\b(pk_live_[a-zA-Z0-9]{24,})\b`),
			severity:   "medium",
			confidence: 0.95,
			message:    "Stripe Publishable Key detected (less sensitive)",
		},

		// Slack
		{
			name:       "slack_token",
			regex:      regexp.MustCompile(`\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*)\b`),
			severity:   "critical",
			confidence: 0.90,
			message:    "Slack Token detected",
		},
		{
			name:       "slack_webhook",
			regex:      regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`),
			severity:   "high",
			confidence: 0.95,
			message:    "Slack Webhook URL detected",
		},

		// Google
		{
			name:       "google_api_key",
			regex:      regexp.MustCompile(`\b(AIza[0-9A-Za-z-_]{35})\b`),
			severity:   "high",
			confidence: 0.90,
			message:    "Google API Key detected",
		},

		// Generic patterns
		{
			name:       "bearer_token",
			regex:      regexp.MustCompile(`(?i)(bearer\s+)[a-zA-Z0-9_\-\.=]{20,}`),
			severity:   "high",
			confidence: 0.70,
			message:    "Bearer token detected",
		},
		{
			name:       "basic_auth",
			regex:      regexp.MustCompile(`(?i)(basic\s+)[a-zA-Z0-9+/=]{20,}`),
			severity:   "high",
			confidence: 0.70,
			message:    "Basic auth credentials detected",
		},
		{
			name:       "api_key_generic",
			regex:      regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?`),
			severity:   "high",
			confidence: 0.60,
			message:    "Generic API key detected",
		},
		{
			name:       "secret_generic",
			regex:      regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`),
			severity:   "high",
			confidence: 0.50,
			message:    "Potential secret or password detected",
		},

		// Private keys
		{
			name:       "rsa_private_key",
			regex:      regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			severity:   "critical",
			confidence: 0.99,
			message:    "RSA Private Key detected",
		},
		{
			name:       "openssh_private_key",
			regex:      regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
			severity:   "critical",
			confidence: 0.99,
			message:    "OpenSSH Private Key detected",
		},
		{
			name:       "ec_private_key",
			regex:      regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			severity:   "critical",
			confidence: 0.99,
			message:    "EC Private Key detected",
		},
		{
			name:       "pgp_private_key",
			regex:      regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			severity:   "critical",
			confidence: 0.99,
			message:    "PGP Private Key detected",
		},
		{
			name:       "private_key_generic",
			regex:      regexp.MustCompile(`-----BEGIN (\w+ )?PRIVATE KEY-----`),
			severity:   "critical",
			confidence: 0.95,
			message:    "Private Key detected",
		},

		// Database connection strings
		{
			name:       "postgres_uri",
			regex:      regexp.MustCompile(`postgres(ql)?://[^:]+:[^@]+@[^/]+`),
			severity:   "critical",
			confidence: 0.90,
			message:    "PostgreSQL connection string with credentials detected",
		},
		{
			name:       "mysql_uri",
			regex:      regexp.MustCompile(`mysql://[^:]+:[^@]+@[^/]+`),
			severity:   "critical",
			confidence: 0.90,
			message:    "MySQL connection string with credentials detected",
		},
		{
			name:       "mongodb_uri",
			regex:      regexp.MustCompile(`mongodb(\+srv)?://[^:]+:[^@]+@[^/]+`),
			severity:   "critical",
			confidence: 0.90,
			message:    "MongoDB connection string with credentials detected",
		},
		{
			name:       "redis_uri",
			regex:      regexp.MustCompile(`redis://[^:]+:[^@]+@[^/]+`),
			severity:   "critical",
			confidence: 0.90,
			message:    "Redis connection string with credentials detected",
		},

		// JWT
		{
			name:       "jwt_token",
			regex:      regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b`),
			severity:   "medium",
			confidence: 0.85,
			message:    "JWT token detected",
		},

		// npm
		{
			name:       "npm_token",
			regex:      regexp.MustCompile(`\b(npm_[a-zA-Z0-9]{36})\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "NPM access token detected",
		},

		// Twilio
		{
			name:       "twilio_api_key",
			regex:      regexp.MustCompile(`\bSK[a-f0-9]{32}\b`),
			severity:   "high",
			confidence: 0.80,
			message:    "Twilio API Key detected",
		},

		// SendGrid
		{
			name:       "sendgrid_api_key",
			regex:      regexp.MustCompile(`\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b`),
			severity:   "critical",
			confidence: 0.95,
			message:    "SendGrid API Key detected",
		},

		// Mailgun
		{
			name:       "mailgun_api_key",
			regex:      regexp.MustCompile(`\bkey-[a-zA-Z0-9]{32}\b`),
			severity:   "high",
			confidence: 0.80,
			message:    "Mailgun API Key detected",
		},
	}
}

// Name returns the scanner name.
func (s *SecretsScanner) Name() string {
	return "secrets"
}

// Scan analyzes the input for secrets.
func (s *SecretsScanner) Scan(input string) []Finding {
	var findings []Finding

	for _, pattern := range s.patterns {
		matches := pattern.regex.FindAllStringIndex(input, -1)
		for _, match := range matches {
			findings = append(findings, Finding{
				Type:       pattern.name,
				Category:   "secrets",
				Severity:   pattern.severity,
				Confidence: pattern.confidence,
				Message:    pattern.message,
				Location: &Location{
					Start: match[0],
					End:   match[1],
				},
			})
		}
	}

	// Also check for high-entropy strings that might be secrets
	entropyFindings := s.scanHighEntropy(input)
	findings = append(findings, entropyFindings...)

	return findings
}

// scanHighEntropy looks for high-entropy strings that might be secrets.
func (s *SecretsScanner) scanHighEntropy(input string) []Finding {
	var findings []Finding

	// Look for potential hex secrets (32+ chars)
	hexPattern := regexp.MustCompile(`\b[a-fA-F0-9]{32,}\b`)
	hexMatches := hexPattern.FindAllStringIndex(input, -1)
	for _, match := range hexMatches {
		str := input[match[0]:match[1]]
		entropy := calculateEntropy(str)
		if entropy > 3.5 { // High entropy threshold
			findings = append(findings, Finding{
				Type:       "high_entropy_hex",
				Category:   "secrets",
				Severity:   "medium",
				Confidence: entropy / 6.0, // Normalize to 0-1
				Message:    "High-entropy hex string detected (possible secret)",
				Location: &Location{
					Start: match[0],
					End:   match[1],
				},
			})
		}
	}

	// Look for base64-like strings (32+ chars)
	base64Pattern := regexp.MustCompile(`\b[A-Za-z0-9+/]{32,}={0,2}\b`)
	base64Matches := base64Pattern.FindAllStringIndex(input, -1)
	for _, match := range base64Matches {
		str := input[match[0]:match[1]]
		// Skip if it looks like a common word or path
		if isLikelyNotSecret(str) {
			continue
		}
		entropy := calculateEntropy(str)
		if entropy > 4.0 { // Higher threshold for base64
			findings = append(findings, Finding{
				Type:       "high_entropy_base64",
				Category:   "secrets",
				Severity:   "low",
				Confidence: 0.4,
				Message:    "High-entropy base64-like string detected (possible secret)",
				Location: &Location{
					Start: match[0],
					End:   match[1],
				},
			})
		}
	}

	return findings
}

// calculateEntropy calculates the Shannon entropy of a string.
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// isLikelyNotSecret checks if a string is likely not a secret.
func isLikelyNotSecret(s string) bool {
	lower := strings.ToLower(s)

	// Common paths and words
	skipPatterns := []string{
		"application", "documentation", "configuration",
		"implementation", "authentication", "authorization",
		"organization", "notification", "specification",
	}

	for _, pattern := range skipPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// RedactSecret redacts a secret, keeping only first and last few characters.
func RedactSecret(s string, keepChars int) string {
	if len(s) <= keepChars*2 {
		return strings.Repeat("*", len(s))
	}
	return s[:keepChars] + strings.Repeat("*", len(s)-keepChars*2) + s[len(s)-keepChars:]
}
