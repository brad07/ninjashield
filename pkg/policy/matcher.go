package policy

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Matcher evaluates conditions against input.
type Matcher struct {
	// regexCache caches compiled regular expressions
	regexCache map[string]*regexp.Regexp
}

// NewMatcher creates a new Matcher.
func NewMatcher() *Matcher {
	return &Matcher{
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// MatchRule checks if all conditions of a rule match the input.
// All conditions must match for the rule to match (AND logic).
func (m *Matcher) MatchRule(rule *Rule, input *EvaluationInput) bool {
	if !rule.IsEnabled() {
		return false
	}

	for _, cond := range rule.Conditions {
		if !m.MatchCondition(&cond, input) {
			return false
		}
	}

	return true
}

// MatchCondition checks if a single condition matches the input.
func (m *Matcher) MatchCondition(cond *Condition, input *EvaluationInput) bool {
	var matches bool

	switch cond.Type {
	case ConditionCommandPattern:
		matches = m.matchGlob(cond.Pattern, input.Command)

	case ConditionCommandRegex:
		matches = m.matchRegex(cond.Pattern, input.Command)

	case ConditionCommandPrefix:
		matches = m.matchCommandPrefix(cond.Pattern, input)

	case ConditionPathPattern:
		matches = m.matchPathPattern(cond.Pattern, input)

	case ConditionPathRegex:
		matches = m.matchPathRegex(cond.Pattern, input)

	case ConditionContentClass:
		matches = m.matchContentClass(cond, input)

	case ConditionHasFlag:
		pattern := cond.Pattern
		if pattern == "" {
			pattern = cond.Value
		}
		matches = m.matchHasFlag(pattern, input)

	case ConditionCwdPattern:
		matches = m.matchGlob(cond.Pattern, input.Cwd)

	case ConditionPipeToShell:
		matches = m.matchPipeToShell(input)

	default:
		matches = false
	}

	// Apply negation
	if cond.Negate {
		return !matches
	}
	return matches
}

// matchGlob matches a glob pattern against a string.
func (m *Matcher) matchGlob(pattern, s string) bool {
	// Convert glob to regex-like matching
	// Support: * (any chars), ? (single char), ** (any path segment)
	matched, err := filepath.Match(pattern, s)
	if err != nil {
		// If pattern is invalid, try a more flexible approach
		return m.matchFlexibleGlob(pattern, s)
	}
	return matched
}

// matchFlexibleGlob provides more flexible glob matching for command patterns.
func (m *Matcher) matchFlexibleGlob(pattern, s string) bool {
	// Convert glob pattern to regex
	regexPattern := globToRegex(pattern)
	return m.matchRegex(regexPattern, s)
}

// globToRegex converts a glob pattern to a regex pattern.
func globToRegex(glob string) string {
	var result strings.Builder
	result.WriteString("^")

	i := 0
	for i < len(glob) {
		c := glob[i]
		switch c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				// ** matches anything including path separators
				result.WriteString(".*")
				i++
			} else {
				// * matches anything except path separators (for paths) or spaces (for commands)
				result.WriteString("[^ ]*")
			}
		case '?':
			result.WriteString("[^ ]")
		case '.', '+', '^', '$', '(', ')', '{', '}', '[', ']', '|', '\\':
			result.WriteString("\\")
			result.WriteByte(c)
		default:
			result.WriteByte(c)
		}
		i++
	}

	result.WriteString("$")
	return result.String()
}

// matchRegex matches a regex pattern against a string.
func (m *Matcher) matchRegex(pattern, s string) bool {
	re, ok := m.regexCache[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}
		m.regexCache[pattern] = re
	}
	return re.MatchString(s)
}

// matchCommandPrefix matches the command executable (first word) against a pattern.
func (m *Matcher) matchCommandPrefix(pattern string, input *EvaluationInput) bool {
	var cmd string
	if len(input.CommandArgv) > 0 {
		cmd = input.CommandArgv[0]
	} else {
		// Extract first word from command string
		parts := strings.Fields(input.Command)
		if len(parts) == 0 {
			return false
		}
		cmd = parts[0]
	}

	// Handle patterns that might be comma-separated list of commands
	patterns := strings.Split(pattern, ",")
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == cmd || m.matchGlob(p, cmd) {
			return true
		}
	}

	return false
}

// matchPathPattern matches file paths in the command against a glob pattern.
func (m *Matcher) matchPathPattern(pattern string, input *EvaluationInput) bool {
	paths := extractPaths(input)
	for _, path := range paths {
		if m.matchGlob(pattern, path) {
			return true
		}
	}
	return false
}

// matchPathRegex matches file paths in the command against a regex pattern.
func (m *Matcher) matchPathRegex(pattern string, input *EvaluationInput) bool {
	paths := extractPaths(input)
	for _, path := range paths {
		if m.matchRegex(pattern, path) {
			return true
		}
	}
	return false
}

// extractPaths extracts potential file paths from the command.
func extractPaths(input *EvaluationInput) []string {
	var paths []string

	// Use argv if available, otherwise parse command string
	args := input.CommandArgv
	if len(args) == 0 {
		args = strings.Fields(input.Command)
	}

	for _, arg := range args {
		// Skip flags
		if strings.HasPrefix(arg, "-") {
			continue
		}
		// Skip the command itself (first arg)
		if len(paths) == 0 && arg == args[0] {
			continue
		}
		// Consider anything that looks like a path
		if strings.Contains(arg, "/") || strings.Contains(arg, ".") || arg == "~" || strings.HasPrefix(arg, "~") {
			paths = append(paths, arg)
		}
	}

	return paths
}

// matchContentClass checks if any of the input's content classes match.
func (m *Matcher) matchContentClass(cond *Condition, input *EvaluationInput) bool {
	targets := cond.Values
	if cond.Value != "" {
		targets = append(targets, cond.Value)
	}

	for _, class := range input.ContentClasses {
		for _, target := range targets {
			if class == target {
				return true
			}
		}
	}

	return false
}

// matchHasFlag checks if a specific flag is present in the command.
func (m *Matcher) matchHasFlag(flag string, input *EvaluationInput) bool {
	args := input.CommandArgv
	if len(args) == 0 {
		args = strings.Fields(input.Command)
	}

	for _, arg := range args {
		if arg == flag {
			return true
		}
		// Also check for combined short flags like -rf containing -r and -f
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && len(arg) > 1 {
			// It's a short flag group like -rf
			if strings.HasPrefix(flag, "-") && len(flag) == 2 {
				flagChar := flag[1]
				if strings.ContainsRune(arg, rune(flagChar)) {
					return true
				}
			}
		}
	}

	return false
}

// matchPipeToShell detects if the command pipes to a shell interpreter.
func (m *Matcher) matchPipeToShell(input *EvaluationInput) bool {
	cmd := input.Command

	// Common shell interpreters
	shells := []string{"sh", "bash", "zsh", "fish", "ksh", "csh", "tcsh", "dash"}

	// Check for pipe to shell patterns
	for _, shell := range shells {
		patterns := []string{
			"| " + shell,
			"|" + shell,
			"| /" + shell,      // | /bin/sh
			"|/" + shell,       // |/bin/sh
			"| /bin/" + shell,
			"|/bin/" + shell,
			"| /usr/bin/" + shell,
			"|/usr/bin/" + shell,
		}
		for _, p := range patterns {
			if strings.Contains(cmd, p) {
				return true
			}
		}
	}

	// Check for common dangerous patterns
	dangerousPatterns := []string{
		"| sh -",
		"|sh -",
		"| bash -",
		"|bash -",
		"$(",   // Command substitution that could execute downloaded content
		"`",    // Backtick command substitution
	}
	for _, p := range dangerousPatterns {
		if strings.Contains(cmd, p) {
			return true
		}
	}

	return false
}

// ExtractCommandInfo extracts structured information from a command.
type CommandInfo struct {
	Executable string
	Args       []string
	Flags      []string
	Paths      []string
	HasPipe    bool
	PipeTo     string
}

// ParseCommand extracts structured information from a command string.
func ParseCommand(cmd string) *CommandInfo {
	info := &CommandInfo{}

	// Check for pipes
	if idx := strings.Index(cmd, "|"); idx >= 0 {
		info.HasPipe = true
		info.PipeTo = strings.TrimSpace(cmd[idx+1:])
		cmd = cmd[:idx]
	}

	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return info
	}

	info.Executable = parts[0]
	info.Args = parts[1:]

	for _, arg := range info.Args {
		if strings.HasPrefix(arg, "-") {
			info.Flags = append(info.Flags, arg)
		} else if strings.Contains(arg, "/") || strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "~") {
			info.Paths = append(info.Paths, arg)
		}
	}

	return info
}

// MatchLLMRule checks if all conditions of a rule match the LLM input.
func (m *Matcher) MatchLLMRule(rule *Rule, input *LLMEvaluationInput) bool {
	if !rule.IsEnabled() {
		return false
	}

	for _, cond := range rule.Conditions {
		if !m.MatchLLMCondition(&cond, input) {
			return false
		}
	}

	return true
}

// MatchLLMCondition checks if a single condition matches the LLM input.
func (m *Matcher) MatchLLMCondition(cond *Condition, input *LLMEvaluationInput) bool {
	var matches bool

	switch cond.Type {
	case ConditionProviderIs:
		matches = strings.EqualFold(input.Provider, cond.Value)

	case ConditionProviderIn:
		for _, v := range cond.Values {
			if strings.EqualFold(input.Provider, v) {
				matches = true
				break
			}
		}

	case ConditionModelIs:
		matches = strings.EqualFold(input.Model, cond.Value)

	case ConditionModelPattern:
		pattern := cond.Pattern
		if pattern == "" {
			pattern = cond.Value
		}
		matches = m.matchGlob(pattern, input.Model) || m.matchGlob(pattern, strings.ToLower(input.Model))

	case ConditionRequestType:
		matches = strings.EqualFold(input.RequestType, cond.Value)

	case ConditionHasAttachments:
		matches = input.HasAttachments

	case ConditionAttachmentType:
		targets := cond.Values
		if cond.Value != "" {
			targets = append(targets, cond.Value)
		}
		for _, attType := range input.AttachmentTypes {
			for _, target := range targets {
				if strings.EqualFold(attType, target) {
					matches = true
					break
				}
			}
		}

	case ConditionHasTools:
		matches = input.HasTools

	case ConditionHasSystemPrompt:
		matches = input.HasSystemPrompt

	case ConditionMessageCount:
		matches = m.matchThreshold(input.MessageCount, cond.Threshold, cond.Operator)

	case ConditionTokenEstimate:
		matches = m.matchThreshold(input.TokenEstimate, cond.Threshold, cond.Operator)

	case ConditionContentClass:
		// Reuse the same logic as command matching
		targets := cond.Values
		if cond.Value != "" {
			targets = append(targets, cond.Value)
		}
		for _, class := range input.ContentClasses {
			for _, target := range targets {
				if class == target {
					matches = true
					break
				}
			}
		}

	default:
		matches = false
	}

	// Apply negation
	if cond.Negate {
		return !matches
	}
	return matches
}

// matchThreshold compares a value against a threshold using an operator.
func (m *Matcher) matchThreshold(value, threshold int, operator string) bool {
	if operator == "" {
		operator = "gte" // Default: greater than or equal
	}

	switch operator {
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	case "eq":
		return value == threshold
	default:
		return value >= threshold
	}
}
