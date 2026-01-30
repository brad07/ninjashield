// Package redact provides content redaction and transformation capabilities.
package redact

import (
	"regexp"
	"strings"
)

// Redactor performs content redaction.
type Redactor struct {
	patterns map[string]*Pattern
}

// Pattern represents a redaction pattern.
type Pattern struct {
	Name        string
	Regex       *regexp.Regexp
	Replacement string
	Category    string // "secrets", "pii", etc.
}

// RedactionResult represents the result of a redaction operation.
type RedactionResult struct {
	Original     string
	Redacted     string
	Replacements []Replacement
	HasChanges   bool
}

// Replacement represents a single redaction replacement.
type Replacement struct {
	Original    string
	Replacement string
	Category    string
	PatternName string
	Start       int
	End         int
}

// NewRedactor creates a new Redactor with default patterns.
func NewRedactor() *Redactor {
	r := &Redactor{
		patterns: make(map[string]*Pattern),
	}
	r.registerDefaultPatterns()
	return r
}

// registerDefaultPatterns registers built-in redaction patterns.
func (r *Redactor) registerDefaultPatterns() {
	// Secrets patterns
	r.AddPattern("openai_api_key", `sk-[a-zA-Z0-9]{20,}`, "[OPENAI_KEY_REDACTED]", "secrets")
	r.AddPattern("anthropic_api_key", `sk-ant-[a-zA-Z0-9\-]{20,}`, "[ANTHROPIC_KEY_REDACTED]", "secrets")
	r.AddPattern("aws_access_key", `AKIA[0-9A-Z]{16}`, "[AWS_KEY_REDACTED]", "secrets")
	r.AddPattern("aws_secret_key", `(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`, "[AWS_SECRET_REDACTED]", "secrets")
	r.AddPattern("github_token", `gh[pousr]_[A-Za-z0-9_]{36,}`, "[GITHUB_TOKEN_REDACTED]", "secrets")
	r.AddPattern("github_pat", `github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`, "[GITHUB_PAT_REDACTED]", "secrets")
	r.AddPattern("generic_api_key", `(?i)(api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{20,}['\"]?`, "[API_KEY_REDACTED]", "secrets")
	r.AddPattern("bearer_token", `(?i)bearer\s+[a-zA-Z0-9\-_\.]+`, "[BEARER_TOKEN_REDACTED]", "secrets")
	r.AddPattern("jwt_token", `eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`, "[JWT_REDACTED]", "secrets")
	r.AddPattern("private_key", `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, "[PRIVATE_KEY_REDACTED]", "secrets")
	r.AddPattern("password_field", `(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[^\s'"]{8,}['\"]?`, "[PASSWORD_REDACTED]", "secrets")

	// PII patterns
	r.AddPattern("ssn", `\b\d{3}-\d{2}-\d{4}\b`, "[SSN_REDACTED]", "pii")
	r.AddPattern("email", `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, "[EMAIL_REDACTED]", "pii")
	r.AddPattern("phone_us", `\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`, "[PHONE_REDACTED]", "pii")
	r.AddPattern("credit_card", `\b(?:\d{4}[-\s]?){3}\d{4}\b`, "[CREDIT_CARD_REDACTED]", "pii")
	r.AddPattern("ip_address", `\b(?:\d{1,3}\.){3}\d{1,3}\b`, "[IP_REDACTED]", "pii")
}

// AddPattern adds a custom redaction pattern.
func (r *Redactor) AddPattern(name, pattern, replacement, category string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	r.patterns[name] = &Pattern{
		Name:        name,
		Regex:       re,
		Replacement: replacement,
		Category:    category,
	}
	return nil
}

// RemovePattern removes a redaction pattern.
func (r *Redactor) RemovePattern(name string) {
	delete(r.patterns, name)
}

// Redact performs redaction on the given content.
func (r *Redactor) Redact(content string) *RedactionResult {
	result := &RedactionResult{
		Original:     content,
		Redacted:     content,
		Replacements: []Replacement{},
		HasChanges:   false,
	}

	// Apply each pattern
	for _, pattern := range r.patterns {
		matches := pattern.Regex.FindAllStringIndex(result.Redacted, -1)
		if len(matches) == 0 {
			continue
		}

		// Process matches in reverse order to preserve indices
		for i := len(matches) - 1; i >= 0; i-- {
			match := matches[i]
			original := result.Redacted[match[0]:match[1]]

			result.Replacements = append(result.Replacements, Replacement{
				Original:    original,
				Replacement: pattern.Replacement,
				Category:    pattern.Category,
				PatternName: pattern.Name,
				Start:       match[0],
				End:         match[1],
			})

			result.Redacted = result.Redacted[:match[0]] + pattern.Replacement + result.Redacted[match[1]:]
			result.HasChanges = true
		}
	}

	return result
}

// RedactCategory performs redaction only for patterns in the specified category.
func (r *Redactor) RedactCategory(content string, category string) *RedactionResult {
	result := &RedactionResult{
		Original:     content,
		Redacted:     content,
		Replacements: []Replacement{},
		HasChanges:   false,
	}

	for _, pattern := range r.patterns {
		if pattern.Category != category {
			continue
		}

		matches := pattern.Regex.FindAllStringIndex(result.Redacted, -1)
		if len(matches) == 0 {
			continue
		}

		for i := len(matches) - 1; i >= 0; i-- {
			match := matches[i]
			original := result.Redacted[match[0]:match[1]]

			result.Replacements = append(result.Replacements, Replacement{
				Original:    original,
				Replacement: pattern.Replacement,
				Category:    pattern.Category,
				PatternName: pattern.Name,
				Start:       match[0],
				End:         match[1],
			})

			result.Redacted = result.Redacted[:match[0]] + pattern.Replacement + result.Redacted[match[1]:]
			result.HasChanges = true
		}
	}

	return result
}

// RedactSecrets redacts only secrets from the content.
func (r *Redactor) RedactSecrets(content string) *RedactionResult {
	return r.RedactCategory(content, "secrets")
}

// RedactPII redacts only PII from the content.
func (r *Redactor) RedactPII(content string) *RedactionResult {
	return r.RedactCategory(content, "pii")
}

// ContainsSecrets checks if content contains any secrets.
func (r *Redactor) ContainsSecrets(content string) bool {
	for _, pattern := range r.patterns {
		if pattern.Category == "secrets" && pattern.Regex.MatchString(content) {
			return true
		}
	}
	return false
}

// ContainsPII checks if content contains any PII.
func (r *Redactor) ContainsPII(content string) bool {
	for _, pattern := range r.patterns {
		if pattern.Category == "pii" && pattern.Regex.MatchString(content) {
			return true
		}
	}
	return false
}

// GetPatterns returns all registered patterns.
func (r *Redactor) GetPatterns() map[string]*Pattern {
	return r.patterns
}

// Transformer provides content transformation capabilities.
type Transformer struct {
	redactor *Redactor
}

// NewTransformer creates a new Transformer.
func NewTransformer() *Transformer {
	return &Transformer{
		redactor: NewRedactor(),
	}
}

// TransformResult represents the result of a transformation.
type TransformResult struct {
	Original    string
	Transformed string
	Changes     []TransformChange
	HasChanges  bool
}

// TransformChange represents a single transformation change.
type TransformChange struct {
	Type        string // "redact", "replace", "remove"
	Description string
	Original    string
	New         string
}

// Transform applies transformations to content based on options.
func (t *Transformer) Transform(content string, opts TransformOptions) *TransformResult {
	result := &TransformResult{
		Original:    content,
		Transformed: content,
		Changes:     []TransformChange{},
		HasChanges:  false,
	}

	// Apply redactions
	if opts.RedactSecrets {
		redactResult := t.redactor.RedactSecrets(result.Transformed)
		if redactResult.HasChanges {
			result.Transformed = redactResult.Redacted
			result.HasChanges = true
			for _, r := range redactResult.Replacements {
				result.Changes = append(result.Changes, TransformChange{
					Type:        "redact",
					Description: "Redacted secret: " + r.PatternName,
					Original:    r.Original,
					New:         r.Replacement,
				})
			}
		}
	}

	if opts.RedactPII {
		redactResult := t.redactor.RedactPII(result.Transformed)
		if redactResult.HasChanges {
			result.Transformed = redactResult.Redacted
			result.HasChanges = true
			for _, r := range redactResult.Replacements {
				result.Changes = append(result.Changes, TransformChange{
					Type:        "redact",
					Description: "Redacted PII: " + r.PatternName,
					Original:    r.Original,
					New:         r.Replacement,
				})
			}
		}
	}

	// Apply custom replacements
	for _, repl := range opts.CustomReplacements {
		if strings.Contains(result.Transformed, repl.Find) {
			result.Transformed = strings.ReplaceAll(result.Transformed, repl.Find, repl.Replace)
			result.HasChanges = true
			result.Changes = append(result.Changes, TransformChange{
				Type:        "replace",
				Description: "Custom replacement",
				Original:    repl.Find,
				New:         repl.Replace,
			})
		}
	}

	// Remove patterns
	for _, pattern := range opts.RemovePatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(result.Transformed) {
			original := result.Transformed
			result.Transformed = re.ReplaceAllString(result.Transformed, "")
			if original != result.Transformed {
				result.HasChanges = true
				result.Changes = append(result.Changes, TransformChange{
					Type:        "remove",
					Description: "Removed pattern: " + pattern,
					Original:    pattern,
					New:         "",
				})
			}
		}
	}

	return result
}

// TransformOptions specifies transformation options.
type TransformOptions struct {
	RedactSecrets      bool
	RedactPII          bool
	CustomReplacements []CustomReplacement
	RemovePatterns     []string
}

// CustomReplacement represents a custom find/replace operation.
type CustomReplacement struct {
	Find    string
	Replace string
}

// GetRedactor returns the underlying redactor.
func (t *Transformer) GetRedactor() *Redactor {
	return t.redactor
}
