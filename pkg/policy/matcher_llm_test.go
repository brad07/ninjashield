package policy

import (
	"testing"
)

func TestMatcherLLM_ProviderIs(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name     string
		provider string
		value    string
		want     bool
	}{
		{"exact match", "openai", "openai", true},
		{"case insensitive", "OpenAI", "openai", true},
		{"no match", "anthropic", "openai", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{Provider: tt.provider}
			cond := &Condition{Type: ConditionProviderIs, Value: tt.value}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_ProviderIn(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name     string
		provider string
		values   []string
		want     bool
	}{
		{"in list", "openai", []string{"openai", "anthropic"}, true},
		{"not in list", "google", []string{"openai", "anthropic"}, false},
		{"case insensitive", "OpenAI", []string{"openai", "anthropic"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{Provider: tt.provider}
			cond := &Condition{Type: ConditionProviderIn, Values: tt.values}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_ModelIs(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name  string
		model string
		value string
		want  bool
	}{
		{"exact match", "gpt-4", "gpt-4", true},
		{"case insensitive", "GPT-4", "gpt-4", true},
		{"no match", "gpt-3.5-turbo", "gpt-4", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{Model: tt.model}
			cond := &Condition{Type: ConditionModelIs, Value: tt.value}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_ModelPattern(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name    string
		model   string
		pattern string
		want    bool
	}{
		{"wildcard match", "gpt-4-turbo", "gpt-4*", true},
		{"wildcard match 2", "claude-3-opus-20240229", "claude-3*", true},
		{"no match", "gpt-3.5-turbo", "gpt-4*", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{Model: tt.model}
			cond := &Condition{Type: ConditionModelPattern, Pattern: tt.pattern}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_RequestType(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name        string
		requestType string
		value       string
		want        bool
	}{
		{"chat match", "chat", "chat", true},
		{"case insensitive", "Chat", "chat", true},
		{"no match", "embedding", "chat", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{RequestType: tt.requestType}
			cond := &Condition{Type: ConditionRequestType, Value: tt.value}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_HasAttachments(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name           string
		hasAttachments bool
		want           bool
	}{
		{"has attachments", true, true},
		{"no attachments", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{HasAttachments: tt.hasAttachments}
			cond := &Condition{Type: ConditionHasAttachments}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_AttachmentType(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name            string
		attachmentTypes []string
		values          []string
		want            bool
	}{
		{"match single", []string{"image"}, []string{"image"}, true},
		{"match one of many", []string{"image", "file"}, []string{"image"}, true},
		{"no match", []string{"audio"}, []string{"image"}, false},
		{"empty attachments", []string{}, []string{"image"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{AttachmentTypes: tt.attachmentTypes}
			cond := &Condition{Type: ConditionAttachmentType, Values: tt.values}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_HasTools(t *testing.T) {
	m := NewMatcher()

	input := &LLMEvaluationInput{HasTools: true}
	cond := &Condition{Type: ConditionHasTools}
	if !m.MatchLLMCondition(cond, input) {
		t.Error("Expected HasTools to match")
	}

	input = &LLMEvaluationInput{HasTools: false}
	if m.MatchLLMCondition(cond, input) {
		t.Error("Expected HasTools to not match")
	}
}

func TestMatcherLLM_HasSystemPrompt(t *testing.T) {
	m := NewMatcher()

	input := &LLMEvaluationInput{HasSystemPrompt: true}
	cond := &Condition{Type: ConditionHasSystemPrompt}
	if !m.MatchLLMCondition(cond, input) {
		t.Error("Expected HasSystemPrompt to match")
	}

	input = &LLMEvaluationInput{HasSystemPrompt: false}
	if m.MatchLLMCondition(cond, input) {
		t.Error("Expected HasSystemPrompt to not match")
	}
}

func TestMatcherLLM_MessageCount(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name      string
		count     int
		threshold int
		operator  string
		want      bool
	}{
		{"gte default", 10, 5, "", true},
		{"gt match", 10, 5, "gt", true},
		{"gt no match", 5, 5, "gt", false},
		{"gte match", 5, 5, "gte", true},
		{"lt match", 3, 5, "lt", true},
		{"lt no match", 5, 5, "lt", false},
		{"lte match", 5, 5, "lte", true},
		{"eq match", 5, 5, "eq", true},
		{"eq no match", 4, 5, "eq", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &LLMEvaluationInput{MessageCount: tt.count}
			cond := &Condition{Type: ConditionMessageCount, Threshold: tt.threshold, Operator: tt.operator}
			if got := m.MatchLLMCondition(cond, input); got != tt.want {
				t.Errorf("MatchLLMCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMatcherLLM_TokenEstimate(t *testing.T) {
	m := NewMatcher()

	input := &LLMEvaluationInput{TokenEstimate: 5000}
	cond := &Condition{Type: ConditionTokenEstimate, Threshold: 4000, Operator: "gt"}
	if !m.MatchLLMCondition(cond, input) {
		t.Error("Expected TokenEstimate > 4000 to match")
	}

	cond = &Condition{Type: ConditionTokenEstimate, Threshold: 6000, Operator: "gt"}
	if m.MatchLLMCondition(cond, input) {
		t.Error("Expected TokenEstimate > 6000 to not match")
	}
}

func TestMatcherLLM_ContentClass(t *testing.T) {
	m := NewMatcher()

	input := &LLMEvaluationInput{ContentClasses: []string{"secrets", "pii"}}
	cond := &Condition{Type: ConditionContentClass, Value: "secrets"}
	if !m.MatchLLMCondition(cond, input) {
		t.Error("Expected secrets content class to match")
	}

	cond = &Condition{Type: ConditionContentClass, Value: "code"}
	if m.MatchLLMCondition(cond, input) {
		t.Error("Expected code content class to not match")
	}
}

func TestMatcherLLM_Negation(t *testing.T) {
	m := NewMatcher()

	input := &LLMEvaluationInput{Provider: "openai"}
	cond := &Condition{Type: ConditionProviderIs, Value: "anthropic", Negate: true}
	if !m.MatchLLMCondition(cond, input) {
		t.Error("Expected negated condition to match")
	}

	cond = &Condition{Type: ConditionProviderIs, Value: "openai", Negate: true}
	if m.MatchLLMCondition(cond, input) {
		t.Error("Expected negated condition to not match")
	}
}

func TestMatcherLLM_Rule(t *testing.T) {
	m := NewMatcher()

	rule := &Rule{
		ID:   "block-unknown-providers",
		Name: "Block Unknown Providers",
		Conditions: []Condition{
			{Type: ConditionProviderIn, Values: []string{"openai", "anthropic"}, Negate: true},
		},
		Action: Action{
			Decision: DecisionDeny,
			Reason:   "Unknown provider not allowed",
		},
	}

	// Should match (provider not in list)
	input := &LLMEvaluationInput{Provider: "unknown"}
	if !m.MatchLLMRule(rule, input) {
		t.Error("Expected rule to match unknown provider")
	}

	// Should not match (provider in list)
	input = &LLMEvaluationInput{Provider: "openai"}
	if m.MatchLLMRule(rule, input) {
		t.Error("Expected rule to not match openai provider")
	}
}

func TestMatcherLLM_RuleMultipleConditions(t *testing.T) {
	m := NewMatcher()

	rule := &Rule{
		ID:   "block-attachments-from-unknown",
		Name: "Block Attachments from Unknown Providers",
		Conditions: []Condition{
			{Type: ConditionProviderIn, Values: []string{"openai", "anthropic"}, Negate: true},
			{Type: ConditionHasAttachments},
		},
		Action: Action{
			Decision: DecisionDeny,
			Reason:   "Attachments not allowed from unknown providers",
		},
	}

	// Should match (unknown provider + has attachments)
	input := &LLMEvaluationInput{Provider: "unknown", HasAttachments: true}
	if !m.MatchLLMRule(rule, input) {
		t.Error("Expected rule to match")
	}

	// Should not match (known provider + has attachments)
	input = &LLMEvaluationInput{Provider: "openai", HasAttachments: true}
	if m.MatchLLMRule(rule, input) {
		t.Error("Expected rule to not match known provider")
	}

	// Should not match (unknown provider + no attachments)
	input = &LLMEvaluationInput{Provider: "unknown", HasAttachments: false}
	if m.MatchLLMRule(rule, input) {
		t.Error("Expected rule to not match without attachments")
	}
}

func TestMatcherLLM_DisabledRule(t *testing.T) {
	m := NewMatcher()
	enabled := false

	rule := &Rule{
		ID:      "disabled-rule",
		Name:    "Disabled Rule",
		Enabled: &enabled,
		Conditions: []Condition{
			{Type: ConditionProviderIs, Value: "openai"},
		},
		Action: Action{
			Decision: DecisionDeny,
			Reason:   "Should not fire",
		},
	}

	input := &LLMEvaluationInput{Provider: "openai"}
	if m.MatchLLMRule(rule, input) {
		t.Error("Expected disabled rule to not match")
	}
}
