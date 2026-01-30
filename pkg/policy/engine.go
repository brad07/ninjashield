package policy

import (
	"sort"
	"strings"

	"github.com/brad07/ninjashield/pkg/scanners"
)

// Engine evaluates commands against policies using scanners.
type Engine struct {
	policy         *Policy
	matcher        *Matcher
	secretsScanner *scanners.SecretsScanner
	piiScanner     *scanners.PIIScanner
	commandScanner *scanners.CommandScanner

	// Configuration
	enableSecrets  bool
	enablePII      bool
	enableCommands bool
}

// EngineConfig holds configuration for the policy engine.
type EngineConfig struct {
	EnableSecrets  bool
	EnablePII      bool
	EnableCommands bool
}

// DefaultEngineConfig returns the default engine configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		EnableSecrets:  true,
		EnablePII:      true,
		EnableCommands: true,
	}
}

// NewEngine creates a new policy engine with the given policy.
func NewEngine(policy *Policy) *Engine {
	return NewEngineWithConfig(policy, DefaultEngineConfig())
}

// NewEngineWithConfig creates a new policy engine with custom configuration.
func NewEngineWithConfig(policy *Policy, config EngineConfig) *Engine {
	return &Engine{
		policy:         policy,
		matcher:        NewMatcher(),
		secretsScanner: scanners.NewSecretsScanner(),
		piiScanner:     scanners.NewPIIScanner(),
		commandScanner: scanners.NewCommandScanner(),
		enableSecrets:  config.EnableSecrets,
		enablePII:      config.EnablePII,
		enableCommands: config.EnableCommands,
	}
}

// SetPolicy updates the policy used by the engine.
func (e *Engine) SetPolicy(policy *Policy) {
	e.policy = policy
}

// GetPolicy returns the current policy.
func (e *Engine) GetPolicy() *Policy {
	return e.policy
}

// Evaluate evaluates a command against the policy and returns a decision.
func (e *Engine) Evaluate(input *EvaluationInput) *EvaluationResult {
	result := &EvaluationResult{
		Decision:       e.policy.DefaultAction.Decision,
		PolicyID:       e.policy.ID,
		RiskScore:      0,
		RiskCategories: make([]string, 0),
		ReasonCodes:    make([]string, 0),
		Reasons:        []string{e.policy.DefaultAction.Reason},
		MatchedRules:   make([]string, 0),
		Context:        e.policy.DefaultAction.Context,
	}

	// Run scanners and collect findings
	allFindings := e.runScanners(input)

	// Convert scanner findings to content classes for policy matching
	contentClasses := e.findingsToContentClasses(allFindings)
	input.ContentClasses = append(input.ContentClasses, contentClasses...)

	// Add scanner-based risk categories
	for _, finding := range allFindings {
		addUniqueString(&result.RiskCategories, finding.Category)
	}

	// Calculate risk score from scanner findings
	scannerResult := scanners.Aggregate(allFindings)
	result.RiskScore = scannerResult.RiskScore

	// Evaluate policy rules
	matchedRules := e.evaluateRules(input)

	// Process matched rules to determine final decision
	e.processMatchedRules(matchedRules, result)

	// Add scanner findings to context if any critical ones found
	e.addScannerContext(allFindings, result)

	return result
}

// runScanners runs all enabled scanners on the input.
func (e *Engine) runScanners(input *EvaluationInput) []scanners.Finding {
	var allFindings []scanners.Finding

	// Scan the command string
	if e.enableSecrets {
		findings := e.secretsScanner.Scan(input.Command)
		allFindings = append(allFindings, findings...)
	}

	if e.enablePII {
		findings := e.piiScanner.Scan(input.Command)
		allFindings = append(allFindings, findings...)
	}

	if e.enableCommands {
		findings := e.commandScanner.Scan(input.Command)
		allFindings = append(allFindings, findings...)
	}

	return allFindings
}

// findingsToContentClasses converts scanner findings to content class strings.
func (e *Engine) findingsToContentClasses(findings []scanners.Finding) []string {
	classes := make(map[string]bool)

	for _, f := range findings {
		// Add category as content class
		classes[f.Category] = true

		// Add specific type as content class
		classes[f.Type] = true

		// Add severity-based class
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

// ruleMatch holds a matched rule and its details.
type ruleMatch struct {
	rule     *Rule
	priority int
}

// evaluateRules evaluates all policy rules against the input.
func (e *Engine) evaluateRules(input *EvaluationInput) []ruleMatch {
	var matches []ruleMatch

	for i := range e.policy.Rules {
		rule := &e.policy.Rules[i]
		if e.matcher.MatchRule(rule, input) {
			matches = append(matches, ruleMatch{
				rule:     rule,
				priority: rule.Priority,
			})
		}
	}

	// Sort by priority (highest first)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].priority > matches[j].priority
	})

	return matches
}

// processMatchedRules processes matched rules and updates the result.
func (e *Engine) processMatchedRules(matches []ruleMatch, result *EvaluationResult) {
	if len(matches) == 0 {
		return
	}

	// Track highest priority decision
	highestPriority := -1
	var winningRule *Rule

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
			if DecisionPriority(rule.Action.Decision) > DecisionPriority(winningRule.Action.Decision) {
				winningRule = rule
			}
		}
	}

	// Apply winning rule's decision
	if winningRule != nil {
		result.Decision = winningRule.Action.Decision
		result.Reasons = []string{winningRule.Action.Reason}
		result.Context = winningRule.Action.Context

		// Handle rewrite suggestion
		if winningRule.Action.RewriteTo != "" {
			result.Rewrite = &RewriteSuggestion{
				Suggested: winningRule.Action.RewriteTo,
				Reason:    winningRule.Action.RewriteNote,
			}
		}
	}
}

// addScannerContext adds context from scanner findings to the result.
func (e *Engine) addScannerContext(findings []scanners.Finding, result *EvaluationResult) {
	var criticalFindings []string

	for _, f := range findings {
		if f.Severity == "critical" {
			criticalFindings = append(criticalFindings, f.Message)
		}
	}

	if len(criticalFindings) > 0 {
		if result.Context != "" {
			result.Context += ". "
		}
		result.Context += "Scanner alerts: " + strings.Join(criticalFindings, "; ")
	}
}

// addUniqueString adds a string to a slice if not already present.
func addUniqueString(slice *[]string, s string) {
	for _, existing := range *slice {
		if existing == s {
			return
		}
	}
	*slice = append(*slice, s)
}

// EvaluateCommand is a convenience method for evaluating a simple command string.
func (e *Engine) EvaluateCommand(command string) *EvaluationResult {
	return e.Evaluate(&EvaluationInput{
		Command: command,
	})
}

// EvaluateCommandWithContext evaluates a command with additional context.
func (e *Engine) EvaluateCommandWithContext(command, cwd, repoRoot, user, tool string) *EvaluationResult {
	// Parse command into argv
	argv := strings.Fields(command)

	return e.Evaluate(&EvaluationInput{
		Command:     command,
		CommandArgv: argv,
		Cwd:         cwd,
		RepoRoot:    repoRoot,
		User:        user,
		Tool:        tool,
	})
}

// QuickEvaluate performs a quick evaluation without full scanner analysis.
// Useful for performance-sensitive scenarios.
func (e *Engine) QuickEvaluate(command string) *EvaluationResult {
	input := &EvaluationInput{
		Command:     command,
		CommandArgv: strings.Fields(command),
	}

	result := &EvaluationResult{
		Decision:       e.policy.DefaultAction.Decision,
		PolicyID:       e.policy.ID,
		RiskScore:      0,
		RiskCategories: make([]string, 0),
		ReasonCodes:    make([]string, 0),
		Reasons:        []string{e.policy.DefaultAction.Reason},
		MatchedRules:   make([]string, 0),
	}

	// Only evaluate policy rules, skip scanners
	matches := e.evaluateRules(input)
	e.processMatchedRules(matches, result)

	return result
}

// BatchEvaluate evaluates multiple commands and returns results.
func (e *Engine) BatchEvaluate(commands []string) []*EvaluationResult {
	results := make([]*EvaluationResult, len(commands))
	for i, cmd := range commands {
		results[i] = e.EvaluateCommand(cmd)
	}
	return results
}

// IsAllowed returns true if the command would be allowed without prompting.
func (e *Engine) IsAllowed(command string) bool {
	result := e.EvaluateCommand(command)
	return result.Decision == DecisionAllow || result.Decision == DecisionLogOnly
}

// IsBlocked returns true if the command would be blocked.
func (e *Engine) IsBlocked(command string) bool {
	result := e.EvaluateCommand(command)
	return result.Decision == DecisionDeny
}

// RequiresApproval returns true if the command requires user approval.
func (e *Engine) RequiresApproval(command string) bool {
	result := e.EvaluateCommand(command)
	return result.Decision == DecisionAsk
}

// GetRiskLevel returns a human-readable risk level for a command.
func (e *Engine) GetRiskLevel(command string) string {
	result := e.EvaluateCommand(command)
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
