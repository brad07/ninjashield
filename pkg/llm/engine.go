// Package llm provides LLM request evaluation functionality.
package llm

import (
	"context"

	"github.com/brad07/ninjashield/pkg/localllm"
	"github.com/brad07/ninjashield/pkg/policy"
	"github.com/brad07/ninjashield/pkg/scanners"
)

// Engine evaluates LLM requests against policies.
type Engine struct {
	policy         *policy.Policy
	matcher        *policy.Matcher
	secretsScanner *scanners.SecretsScanner
	piiScanner     *scanners.PIIScanner
	llmProvider    localllm.Provider

	// Configuration
	enableSecrets bool
	enablePII     bool
	enableLLM     bool
}

// EngineConfig holds configuration for the LLM engine.
type EngineConfig struct {
	EnableSecrets bool
	EnablePII     bool
	EnableLLM     bool
	LLMProvider   localllm.Provider
}

// DefaultEngineConfig returns the default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		EnableSecrets: true,
		EnablePII:     true,
		EnableLLM:     false, // Off by default
	}
}

// NewEngine creates a new LLM evaluation engine.
func NewEngine(pol *policy.Policy) *Engine {
	return NewEngineWithConfig(pol, DefaultEngineConfig())
}

// NewEngineWithConfig creates a new LLM evaluation engine with custom configuration.
func NewEngineWithConfig(pol *policy.Policy, config EngineConfig) *Engine {
	return &Engine{
		policy:         pol,
		matcher:        policy.NewMatcher(),
		secretsScanner: scanners.NewSecretsScanner(),
		piiScanner:     scanners.NewPIIScanner(),
		llmProvider:    config.LLMProvider,
		enableSecrets:  config.EnableSecrets,
		enablePII:      config.EnablePII,
		enableLLM:      config.EnableLLM,
	}
}

// SetLLMProvider sets the local LLM provider for AI-based scoring.
func (e *Engine) SetLLMProvider(provider localllm.Provider) {
	e.llmProvider = provider
	e.enableLLM = provider != nil
}

// SetPolicy updates the policy used by the engine.
func (e *Engine) SetPolicy(pol *policy.Policy) {
	e.policy = pol
}

// GetPolicy returns the current policy.
func (e *Engine) GetPolicy() *policy.Policy {
	return e.policy
}

// Evaluate evaluates an LLM request against the policy.
func (e *Engine) Evaluate(ctx context.Context, req *Request) *EvaluationResult {
	result := &EvaluationResult{
		Decision:       string(e.policy.DefaultAction.Decision),
		PolicyID:       e.policy.ID,
		RiskScore:      0,
		RiskCategories: make([]string, 0),
		ReasonCodes:    make([]string, 0),
		Reasons:        []string{e.policy.DefaultAction.Reason},
		MatchedRules:   make([]string, 0),
	}

	// Get all content for scanning
	content := req.GetAllContent()

	// Run scanners
	var allFindings []scanners.Finding
	var secretsCount, piiCount int

	if e.enableSecrets {
		findings := e.secretsScanner.Scan(content)
		allFindings = append(allFindings, findings...)
		secretsCount = len(findings)
		if secretsCount > 0 {
			addUniqueString(&result.RiskCategories, "secrets")
		}
	}

	if e.enablePII {
		findings := e.piiScanner.Scan(content)
		allFindings = append(allFindings, findings...)
		piiCount = len(findings)
		if piiCount > 0 {
			addUniqueString(&result.RiskCategories, "pii")
		}
	}

	// Calculate risk score from scanner findings
	scannerResult := scanners.Aggregate(allFindings)
	result.RiskScore = scannerResult.RiskScore

	// Build content classes from findings
	contentClasses := e.findingsToContentClasses(allFindings)

	// Build LLM evaluation input
	summary := req.GetContentSummary()
	llmInput := &policy.LLMEvaluationInput{
		Provider:        string(req.Provider),
		Model:           req.Model,
		Endpoint:        req.Endpoint,
		RequestType:     string(req.RequestType),
		HasSystemPrompt: req.SystemPrompt != "",
		MessageCount:    len(req.Messages),
		TokenEstimate:   estimateTokens(content),
		ContentClasses:  contentClasses,
		HasAttachments:  summary.HasAttachments,
		AttachmentTypes: summary.AttachmentTypes,
		HasTools:        summary.HasTools,
		User:            req.User,
		Tool:            req.Tool,
		Content:         content,
	}

	// Evaluate policy rules
	matchedRules := e.evaluateRules(llmInput)

	// Process matched rules
	e.processMatchedRules(matchedRules, result)

	// Optional LLM scoring
	if e.enableLLM && e.llmProvider != nil {
		llmSummary := localllm.ContentSummary{
			Provider:        string(req.Provider),
			Model:           req.Model,
			RequestType:     string(req.RequestType),
			MessageCount:    len(req.Messages),
			HasAttachments:  summary.HasAttachments,
			HasTools:        summary.HasTools,
			DetectedSecrets: secretsCount,
			DetectedPII:     piiCount,
			ContentClasses:  contentClasses,
			ContentPreview:  truncateContent(content, 500),
		}

		assessment, err := e.llmProvider.AssessContent(ctx, llmSummary)
		if err == nil && assessment != nil {
			// Merge LLM assessment (advisory only)
			e.mergeLLMAssessment(assessment, result)
		}
	}

	// Build redactions if secrets or PII found and decision allows
	if result.Decision == string(policy.DecisionRedact) ||
	   (len(allFindings) > 0 && result.Decision != string(policy.DecisionDeny)) {
		result.Redactions = e.buildRedactions(allFindings)
	}

	return result
}

// EvaluateRequest is a convenience method for evaluating a parsed request.
func (e *Engine) EvaluateRequest(req *Request) *EvaluationResult {
	return e.Evaluate(context.Background(), req)
}

// ruleMatch holds a matched rule and its details.
type ruleMatch struct {
	rule     *policy.Rule
	priority int
}

// evaluateRules evaluates all policy rules against the LLM input.
func (e *Engine) evaluateRules(input *policy.LLMEvaluationInput) []ruleMatch {
	var matches []ruleMatch

	for i := range e.policy.Rules {
		rule := &e.policy.Rules[i]
		if e.matcher.MatchLLMRule(rule, input) {
			matches = append(matches, ruleMatch{
				rule:     rule,
				priority: rule.Priority,
			})
		}
	}

	return matches
}

// processMatchedRules processes matched rules and updates the result.
func (e *Engine) processMatchedRules(matches []ruleMatch, result *EvaluationResult) {
	if len(matches) == 0 {
		return
	}

	// Track highest priority decision
	highestPriority := -1
	var winningRule *policy.Rule

	for _, match := range matches {
		rule := match.rule

		// Add to matched rules
		result.MatchedRules = append(result.MatchedRules, rule.ID)

		// Collect reason codes
		if rule.Action.ReasonCode != "" {
			addUniqueString(&result.ReasonCodes, rule.Action.ReasonCode)
		}

		// Collect risk categories
		if rule.RiskCategory != "" {
			addUniqueString(&result.RiskCategories, string(rule.RiskCategory))
		}

		// Update risk score (take max)
		if rule.RiskScore > result.RiskScore {
			result.RiskScore = rule.RiskScore
		}

		// Determine winning rule by priority
		if rule.Priority > highestPriority {
			highestPriority = rule.Priority
			winningRule = rule
		} else if rule.Priority == highestPriority {
			// Same priority - use decision priority (DENY > ASK > ALLOW)
			if policy.DecisionPriority(rule.Action.Decision) > policy.DecisionPriority(winningRule.Action.Decision) {
				winningRule = rule
			}
		}
	}

	// Apply winning rule's decision
	if winningRule != nil {
		result.Decision = string(winningRule.Action.Decision)
		result.Reasons = []string{winningRule.Action.Reason}
		result.Context = winningRule.Action.Context
	}
}

// mergeLLMAssessment merges LLM assessment into the result (advisory).
func (e *Engine) mergeLLMAssessment(assessment *localllm.RiskAssessment, result *EvaluationResult) {
	// Add LLM risk categories
	for _, cat := range assessment.RiskCategories {
		addUniqueString(&result.RiskCategories, cat)
	}

	// Adjust risk score (weighted average, LLM is advisory)
	if assessment.Confidence > 0.5 {
		// Only factor in high-confidence assessments
		llmWeight := 0.3 // 30% weight for LLM
		result.RiskScore = int(float64(result.RiskScore)*(1-llmWeight) + float64(assessment.RiskScore)*llmWeight)
	}

	// Add LLM explanation to context
	if assessment.Explanation != "" && result.Context != "" {
		result.Context += ". AI analysis: " + assessment.Explanation
	} else if assessment.Explanation != "" {
		result.Context = "AI analysis: " + assessment.Explanation
	}
}

// buildRedactions creates redaction entries from findings.
func (e *Engine) buildRedactions(findings []scanners.Finding) []Redaction {
	var redactions []Redaction

	for _, f := range findings {
		if f.Location != nil {
			redactions = append(redactions, Redaction{
				Field:       "content",
				Type:        f.Category,
				Original:    "[REDACTED]", // Don't store actual value
				Replacement: getMaskForType(f.Category),
				Reason:      f.Message,
			})
		}
	}

	return redactions
}

// findingsToContentClasses converts scanner findings to content class strings.
func (e *Engine) findingsToContentClasses(findings []scanners.Finding) []string {
	classes := make(map[string]bool)

	for _, f := range findings {
		classes[f.Category] = true
		classes[f.Type] = true

		if f.Severity == "critical" || f.Severity == "high" {
			classes["high_risk_"+f.Category] = true
		}
	}

	result := make([]string, 0, len(classes))
	for class := range classes {
		result = append(result, class)
	}
	return result
}

// Helper functions

func addUniqueString(slice *[]string, s string) {
	for _, existing := range *slice {
		if existing == s {
			return
		}
	}
	*slice = append(*slice, s)
}

func estimateTokens(content string) int {
	// Rough estimate: ~4 characters per token for English
	return len(content) / 4
}

func truncateContent(content string, maxLen int) string {
	if len(content) <= maxLen {
		return content
	}
	return content[:maxLen] + "..."
}

func getMaskForType(category string) string {
	switch category {
	case "secrets":
		return "[SECRET_REDACTED]"
	case "pii":
		return "[PII_REDACTED]"
	default:
		return "[REDACTED]"
	}
}

// QuickEvaluate performs evaluation without LLM scoring (for low-latency scenarios).
func (e *Engine) QuickEvaluate(req *Request) *EvaluationResult {
	// Temporarily disable LLM
	origLLM := e.enableLLM
	e.enableLLM = false
	defer func() { e.enableLLM = origLLM }()

	return e.Evaluate(context.Background(), req)
}

// IsAllowed returns true if the request would be allowed.
func (e *Engine) IsAllowed(req *Request) bool {
	result := e.QuickEvaluate(req)
	return result.Decision == string(policy.DecisionAllow) ||
	       result.Decision == string(policy.DecisionLogOnly)
}

// IsBlocked returns true if the request would be blocked.
func (e *Engine) IsBlocked(req *Request) bool {
	result := e.QuickEvaluate(req)
	return result.Decision == string(policy.DecisionDeny)
}

// RequiresApproval returns true if the request requires user approval.
func (e *Engine) RequiresApproval(req *Request) bool {
	result := e.QuickEvaluate(req)
	return result.Decision == string(policy.DecisionAsk)
}

// GetRiskLevel returns a human-readable risk level for a request.
func (e *Engine) GetRiskLevel(req *Request) string {
	result := e.QuickEvaluate(req)
	switch {
	case result.RiskScore >= 80:
		return "critical"
	case result.RiskScore >= 60:
		return "high"
	case result.RiskScore >= 40:
		return "medium"
	case result.RiskScore >= 20:
		return "low"
	default:
		return "minimal"
	}
}

// CreateLLMPolicy creates a basic LLM policy with common rules.
func CreateLLMPolicy() *policy.Policy {
	return &policy.Policy{
		ID:          "llm-default",
		Name:        "Default LLM Policy",
		Version:     "1.0.0",
		Description: "Default policy for LLM API requests",
		DefaultAction: policy.Action{
			Decision: policy.DecisionAsk,
			Reason:   "LLM request requires approval by default",
		},
		Rules: []policy.Rule{
			{
				ID:           "allow-known-providers",
				Name:         "Allow Known Providers",
				Priority:     50,
				RiskCategory: "",
				Conditions: []policy.Condition{
					{Type: policy.ConditionProviderIn, Values: []string{"openai", "anthropic", "google"}},
				},
				Action: policy.Action{
					Decision: policy.DecisionAllow,
					Reason:   "Request to known provider",
				},
			},
			{
				ID:           "block-unknown-providers",
				Name:         "Block Unknown Providers",
				Priority:     100,
				RiskScore:    80,
				RiskCategory: policy.RiskCategoryExfiltration,
				Conditions: []policy.Condition{
					{Type: policy.ConditionProviderIn, Values: []string{"openai", "anthropic", "google", "azure_openai", "ollama"}, Negate: true},
				},
				Action: policy.Action{
					Decision:   policy.DecisionDeny,
					Reason:     "Unknown LLM provider not allowed",
					ReasonCode: "UNKNOWN_PROVIDER",
				},
			},
			{
				ID:           "block-secrets",
				Name:         "Block Requests with Secrets",
				Priority:     100,
				RiskScore:    90,
				RiskCategory: policy.RiskCategorySecrets,
				Conditions: []policy.Condition{
					{Type: policy.ConditionContentClass, Value: "secrets"},
				},
				Action: policy.Action{
					Decision:   policy.DecisionDeny,
					Reason:     "Request contains detected secrets",
					ReasonCode: "SECRETS_DETECTED",
				},
			},
			{
				ID:           "ask-for-pii",
				Name:         "Ask for PII",
				Priority:     80,
				RiskScore:    60,
				RiskCategory: policy.RiskCategoryPII,
				Conditions: []policy.Condition{
					{Type: policy.ConditionContentClass, Value: "pii"},
				},
				Action: policy.Action{
					Decision:   policy.DecisionAsk,
					Reason:     "Request contains PII - approval required",
					ReasonCode: "PII_DETECTED",
				},
			},
			{
				ID:           "ask-for-attachments",
				Name:         "Ask for Attachments",
				Priority:     70,
				RiskScore:    50,
				RiskCategory: policy.RiskCategoryExfiltration,
				Conditions: []policy.Condition{
					{Type: policy.ConditionHasAttachments},
				},
				Action: policy.Action{
					Decision:   policy.DecisionAsk,
					Reason:     "Request includes attachments - approval required",
					ReasonCode: "HAS_ATTACHMENTS",
				},
			},
		},
	}
}
