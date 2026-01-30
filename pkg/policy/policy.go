// Package policy implements the NinjaShield policy engine.
package policy

import (
	"errors"
	"fmt"
	"strings"
)

// Decision represents a policy decision.
type Decision string

const (
	DecisionAllow     Decision = "ALLOW"
	DecisionDeny      Decision = "DENY"
	DecisionAsk       Decision = "ASK" // Require approval
	DecisionRedact    Decision = "REDACT"
	DecisionTransform Decision = "TRANSFORM"
	DecisionLogOnly   Decision = "LOG_ONLY"
)

// Priority levels for decisions (higher = takes precedence)
var decisionPriority = map[Decision]int{
	DecisionDeny:      100,
	DecisionAsk:       80,
	DecisionRedact:    60,
	DecisionTransform: 50,
	DecisionLogOnly:   20,
	DecisionAllow:     10,
}

// ConditionType represents the type of match condition.
type ConditionType string

const (
	// Command-related conditions
	// ConditionCommandPattern matches against the full command string (glob)
	ConditionCommandPattern ConditionType = "command_pattern"
	// ConditionCommandRegex matches against the full command string (regex)
	ConditionCommandRegex ConditionType = "command_regex"
	// ConditionCommandPrefix matches the command executable (first word)
	ConditionCommandPrefix ConditionType = "command_prefix"
	// ConditionPathPattern matches against file paths in the command (glob)
	ConditionPathPattern ConditionType = "path_pattern"
	// ConditionPathRegex matches against file paths in the command (regex)
	ConditionPathRegex ConditionType = "path_regex"
	// ConditionContentClass matches against detected content classes from scanners
	ConditionContentClass ConditionType = "content_class"
	// ConditionHasFlag checks if a specific flag is present
	ConditionHasFlag ConditionType = "has_flag"
	// ConditionCwdPattern matches the current working directory (glob)
	ConditionCwdPattern ConditionType = "cwd_pattern"
	// ConditionPipeToShell detects piping to shell interpreters
	ConditionPipeToShell ConditionType = "pipe_to_shell"

	// LLM-related conditions
	// ConditionProviderIs matches a specific LLM provider
	ConditionProviderIs ConditionType = "provider_is"
	// ConditionProviderIn checks if provider is in a list
	ConditionProviderIn ConditionType = "provider_in"
	// ConditionModelIs matches a specific model name exactly
	ConditionModelIs ConditionType = "model_is"
	// ConditionModelPattern matches model name against a pattern (glob)
	ConditionModelPattern ConditionType = "model_pattern"
	// ConditionRequestType matches the LLM request type (chat, completion, embedding, etc.)
	ConditionRequestType ConditionType = "request_type"
	// ConditionHasAttachments checks if request contains attachments
	ConditionHasAttachments ConditionType = "has_attachments"
	// ConditionAttachmentType checks attachment types
	ConditionAttachmentType ConditionType = "attachment_type"
	// ConditionHasTools checks if request includes tool definitions
	ConditionHasTools ConditionType = "has_tools"
	// ConditionHasSystemPrompt checks if request has a system prompt
	ConditionHasSystemPrompt ConditionType = "has_system_prompt"
	// ConditionMessageCount checks number of messages (threshold)
	ConditionMessageCount ConditionType = "message_count"
	// ConditionTokenEstimate checks estimated token count (threshold)
	ConditionTokenEstimate ConditionType = "token_estimate"
)

// RiskCategory represents a category of risk.
type RiskCategory string

const (
	RiskCategorySecrets     RiskCategory = "secrets"
	RiskCategoryPII         RiskCategory = "pii"
	RiskCategoryDestructive RiskCategory = "destructive"
	RiskCategoryNetwork     RiskCategory = "network"
	RiskCategoryPrivileged  RiskCategory = "privileged"
	RiskCategoryInstall     RiskCategory = "install"
	RiskCategoryExfiltration RiskCategory = "exfiltration"
	RiskCategorySensitiveRead RiskCategory = "sensitive_read"
)

// Rule represents a single policy rule.
type Rule struct {
	ID           string       `yaml:"id"`
	Name         string       `yaml:"name"`
	Description  string       `yaml:"description,omitempty"`
	Enabled      *bool        `yaml:"enabled,omitempty"` // Defaults to true if nil
	Priority     int          `yaml:"priority"`          // Higher = evaluated first
	RiskCategory RiskCategory `yaml:"risk_category,omitempty"`
	RiskScore    int          `yaml:"risk_score,omitempty"` // 0-100
	Conditions   []Condition  `yaml:"conditions"`
	Action       Action       `yaml:"action"`
}

// IsEnabled returns whether the rule is enabled.
func (r *Rule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// Condition represents a match condition for a rule.
type Condition struct {
	Type      ConditionType `yaml:"type"`
	Pattern   string        `yaml:"pattern,omitempty"`   // For pattern-based conditions
	Value     string        `yaml:"value,omitempty"`     // For value-based conditions (e.g., content_class)
	Values    []string      `yaml:"values,omitempty"`    // For multi-value conditions
	Negate    bool          `yaml:"negate,omitempty"`    // If true, condition matches when pattern doesn't match
	Threshold int           `yaml:"threshold,omitempty"` // For numeric threshold conditions (message_count, token_estimate)
	Operator  string        `yaml:"operator,omitempty"`  // Comparison operator: "gt", "gte", "lt", "lte", "eq" (default: "gte")
}

// Action represents what to do when a rule matches.
type Action struct {
	Decision    Decision `yaml:"decision"`
	Reason      string   `yaml:"reason"`
	ReasonCode  string   `yaml:"reason_code,omitempty"`
	RewriteTo   string   `yaml:"rewrite_to,omitempty"`
	RewriteNote string   `yaml:"rewrite_note,omitempty"`
	Context     string   `yaml:"context,omitempty"` // Additional context for the user
}

// Policy represents a complete policy configuration.
type Policy struct {
	ID            string `yaml:"id"`
	Name          string `yaml:"name"`
	Version       string `yaml:"version"`
	Description   string `yaml:"description,omitempty"`
	DefaultAction Action `yaml:"default_action"`
	Rules         []Rule `yaml:"rules"`
}

// Validate validates the policy and returns an error if invalid.
func (p *Policy) Validate() error {
	var errs []string

	if p.ID == "" {
		errs = append(errs, "policy id is required")
	}
	if p.Name == "" {
		errs = append(errs, "policy name is required")
	}
	if p.Version == "" {
		errs = append(errs, "policy version is required")
	}

	// Validate default action
	if err := p.DefaultAction.Validate(); err != nil {
		errs = append(errs, fmt.Sprintf("invalid default_action: %v", err))
	}

	// Validate rules
	ruleIDs := make(map[string]bool)
	for i, rule := range p.Rules {
		if err := rule.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("rule[%d]: %v", i, err))
		}
		if rule.ID != "" {
			if ruleIDs[rule.ID] {
				errs = append(errs, fmt.Sprintf("duplicate rule id: %s", rule.ID))
			}
			ruleIDs[rule.ID] = true
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Validate validates a rule and returns an error if invalid.
func (r *Rule) Validate() error {
	var errs []string

	if r.ID == "" {
		errs = append(errs, "rule id is required")
	}
	if r.Name == "" {
		errs = append(errs, "rule name is required")
	}
	if len(r.Conditions) == 0 {
		errs = append(errs, "at least one condition is required")
	}

	// Validate conditions
	for i, cond := range r.Conditions {
		if err := cond.Validate(); err != nil {
			errs = append(errs, fmt.Sprintf("condition[%d]: %v", i, err))
		}
	}

	// Validate action
	if err := r.Action.Validate(); err != nil {
		errs = append(errs, fmt.Sprintf("action: %v", err))
	}

	// Validate risk score
	if r.RiskScore < 0 || r.RiskScore > 100 {
		errs = append(errs, "risk_score must be between 0 and 100")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// Validate validates a condition and returns an error if invalid.
func (c *Condition) Validate() error {
	validTypes := map[ConditionType]bool{
		// Command conditions
		ConditionCommandPattern: true,
		ConditionCommandRegex:   true,
		ConditionCommandPrefix:  true,
		ConditionPathPattern:    true,
		ConditionPathRegex:      true,
		ConditionContentClass:   true,
		ConditionHasFlag:        true,
		ConditionCwdPattern:     true,
		ConditionPipeToShell:    true,
		// LLM conditions
		ConditionProviderIs:      true,
		ConditionProviderIn:      true,
		ConditionModelIs:         true,
		ConditionModelPattern:    true,
		ConditionRequestType:     true,
		ConditionHasAttachments:  true,
		ConditionAttachmentType:  true,
		ConditionHasTools:        true,
		ConditionHasSystemPrompt: true,
		ConditionMessageCount:    true,
		ConditionTokenEstimate:   true,
	}

	if !validTypes[c.Type] {
		return fmt.Errorf("invalid condition type: %s", c.Type)
	}

	// Check that pattern-based conditions have a pattern
	patternTypes := map[ConditionType]bool{
		ConditionCommandPattern: true,
		ConditionCommandRegex:   true,
		ConditionCommandPrefix:  true,
		ConditionPathPattern:    true,
		ConditionPathRegex:      true,
		ConditionCwdPattern:     true,
		ConditionHasFlag:        true,
		ConditionModelPattern:   true,
	}
	if patternTypes[c.Type] && c.Pattern == "" && c.Value == "" {
		return fmt.Errorf("condition type %s requires pattern or value", c.Type)
	}

	// Check value-based conditions
	valueTypes := map[ConditionType]bool{
		ConditionProviderIs:     true,
		ConditionModelIs:        true,
		ConditionRequestType:    true,
		ConditionAttachmentType: true,
	}
	if valueTypes[c.Type] && c.Value == "" && len(c.Values) == 0 {
		return fmt.Errorf("condition type %s requires value or values", c.Type)
	}

	// Check that content_class has value or values
	if c.Type == ConditionContentClass && c.Value == "" && len(c.Values) == 0 {
		return errors.New("content_class condition requires value or values")
	}

	// Check that provider_in has values
	if c.Type == ConditionProviderIn && len(c.Values) == 0 {
		return errors.New("provider_in condition requires values list")
	}

	return nil
}

// Validate validates an action and returns an error if invalid.
func (a *Action) Validate() error {
	validDecisions := map[Decision]bool{
		DecisionAllow:     true,
		DecisionDeny:      true,
		DecisionAsk:       true,
		DecisionRedact:    true,
		DecisionTransform: true,
		DecisionLogOnly:   true,
	}

	if !validDecisions[a.Decision] {
		return fmt.Errorf("invalid decision: %s", a.Decision)
	}

	if a.Reason == "" {
		return errors.New("reason is required")
	}

	return nil
}

// EvaluationInput holds the input for policy evaluation.
type EvaluationInput struct {
	Command        string            // Full command string
	CommandArgv    []string          // Parsed command arguments
	Cwd            string            // Current working directory
	RepoRoot       string            // Repository root (if applicable)
	User           string            // User executing the command
	Tool           string            // Tool name (claude_code, codex, etc.)
	ContentClasses []string          // Detected content classes from scanners
	Metadata       map[string]string // Additional metadata
}

// LLMEvaluationInput holds the input for LLM request policy evaluation.
type LLMEvaluationInput struct {
	// Provider and model info
	Provider    string // Provider name (openai, anthropic, etc.)
	Model       string // Model name
	Endpoint    string // API endpoint
	RequestType string // Request type (chat, completion, embedding, etc.)

	// Content info
	HasSystemPrompt bool     // Whether request has system prompt
	MessageCount    int      // Number of messages
	TokenEstimate   int      // Estimated token count
	ContentClasses  []string // Detected content classes from scanners

	// Attachments
	HasAttachments  bool     // Whether request has attachments
	AttachmentTypes []string // Types of attachments (image, file, etc.)

	// Tools
	HasTools bool // Whether request includes tool definitions

	// Context
	User string // User making the request
	Tool string // Tool name (claude_code, etc.)

	// Full content for scanning
	Content string // All text content concatenated
}

// EvaluationResult holds the result of evaluating a command against policy.
type EvaluationResult struct {
	Decision       Decision           `json:"decision"`
	RiskScore      int                `json:"risk_score"`
	RiskCategories []string           `json:"risk_categories"`
	ReasonCodes    []string           `json:"reason_codes"`
	Reasons        []string           `json:"reasons"`
	PolicyID       string             `json:"policy_id"`
	MatchedRules   []string           `json:"matched_rules"`
	Rewrite        *RewriteSuggestion `json:"rewrite,omitempty"`
	Context        string             `json:"context"`
}

// RewriteSuggestion holds a suggested command rewrite.
type RewriteSuggestion struct {
	Suggested string `json:"suggested"`
	Reason    string `json:"reason"`
}

// DecisionPriority returns the priority of a decision (higher = takes precedence).
func DecisionPriority(d Decision) int {
	if p, ok := decisionPriority[d]; ok {
		return p
	}
	return 0
}
