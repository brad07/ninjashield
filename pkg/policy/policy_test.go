package policy

import (
	"testing"
)

func TestPolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		policy  Policy
		wantErr bool
	}{
		{
			name: "valid minimal policy",
			policy: Policy{
				ID:      "test",
				Name:    "Test Policy",
				Version: "1.0.0",
				DefaultAction: Action{
					Decision: DecisionAsk,
					Reason:   "Default action",
				},
				Rules: []Rule{
					{
						ID:   "rule1",
						Name: "Test Rule",
						Conditions: []Condition{
							{Type: ConditionCommandPrefix, Pattern: "ls"},
						},
						Action: Action{
							Decision: DecisionAllow,
							Reason:   "Safe command",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing policy id",
			policy: Policy{
				Name:    "Test Policy",
				Version: "1.0.0",
				DefaultAction: Action{
					Decision: DecisionAsk,
					Reason:   "Default",
				},
			},
			wantErr: true,
		},
		{
			name: "missing policy name",
			policy: Policy{
				ID:      "test",
				Version: "1.0.0",
				DefaultAction: Action{
					Decision: DecisionAsk,
					Reason:   "Default",
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate rule ids",
			policy: Policy{
				ID:      "test",
				Name:    "Test Policy",
				Version: "1.0.0",
				DefaultAction: Action{
					Decision: DecisionAsk,
					Reason:   "Default",
				},
				Rules: []Rule{
					{
						ID:   "rule1",
						Name: "Rule 1",
						Conditions: []Condition{
							{Type: ConditionCommandPrefix, Pattern: "ls"},
						},
						Action: Action{Decision: DecisionAllow, Reason: "Allow"},
					},
					{
						ID:   "rule1", // Duplicate!
						Name: "Rule 2",
						Conditions: []Condition{
							{Type: ConditionCommandPrefix, Pattern: "cat"},
						},
						Action: Action{Decision: DecisionAllow, Reason: "Allow"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid rule - no conditions",
			policy: Policy{
				ID:      "test",
				Name:    "Test Policy",
				Version: "1.0.0",
				DefaultAction: Action{
					Decision: DecisionAsk,
					Reason:   "Default",
				},
				Rules: []Rule{
					{
						ID:         "rule1",
						Name:       "Rule 1",
						Conditions: []Condition{}, // Empty!
						Action:     Action{Decision: DecisionAllow, Reason: "Allow"},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid risk score",
			policy: Policy{
				ID:      "test",
				Name:    "Test Policy",
				Version: "1.0.0",
				DefaultAction: Action{
					Decision: DecisionAsk,
					Reason:   "Default",
				},
				Rules: []Rule{
					{
						ID:        "rule1",
						Name:      "Rule 1",
						RiskScore: 150, // Invalid!
						Conditions: []Condition{
							{Type: ConditionCommandPrefix, Pattern: "rm"},
						},
						Action: Action{Decision: DecisionDeny, Reason: "Deny"},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Policy.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConditionValidation(t *testing.T) {
	tests := []struct {
		name    string
		cond    Condition
		wantErr bool
	}{
		{
			name:    "valid command_pattern",
			cond:    Condition{Type: ConditionCommandPattern, Pattern: "rm *"},
			wantErr: false,
		},
		{
			name:    "valid command_regex",
			cond:    Condition{Type: ConditionCommandRegex, Pattern: "^rm\\s+-rf"},
			wantErr: false,
		},
		{
			name:    "valid content_class with value",
			cond:    Condition{Type: ConditionContentClass, Value: "secrets"},
			wantErr: false,
		},
		{
			name:    "valid content_class with values",
			cond:    Condition{Type: ConditionContentClass, Values: []string{"secrets", "pii"}},
			wantErr: false,
		},
		{
			name:    "valid pipe_to_shell (no pattern needed)",
			cond:    Condition{Type: ConditionPipeToShell},
			wantErr: false,
		},
		{
			name:    "invalid condition type",
			cond:    Condition{Type: "invalid_type", Pattern: "test"},
			wantErr: true,
		},
		{
			name:    "command_pattern without pattern",
			cond:    Condition{Type: ConditionCommandPattern},
			wantErr: true,
		},
		{
			name:    "content_class without value or values",
			cond:    Condition{Type: ConditionContentClass},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cond.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Condition.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestActionValidation(t *testing.T) {
	tests := []struct {
		name    string
		action  Action
		wantErr bool
	}{
		{
			name:    "valid allow action",
			action:  Action{Decision: DecisionAllow, Reason: "Safe command"},
			wantErr: false,
		},
		{
			name:    "valid deny action",
			action:  Action{Decision: DecisionDeny, Reason: "Dangerous"},
			wantErr: false,
		},
		{
			name:    "valid ask action with rewrite",
			action:  Action{Decision: DecisionAsk, Reason: "Needs approval", RewriteTo: "safe-cmd", RewriteNote: "Safer alternative"},
			wantErr: false,
		},
		{
			name:    "invalid decision",
			action:  Action{Decision: "INVALID", Reason: "Test"},
			wantErr: true,
		},
		{
			name:    "missing reason",
			action:  Action{Decision: DecisionAllow},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.action.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Action.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRuleIsEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name    string
		enabled *bool
		want    bool
	}{
		{"nil (default enabled)", nil, true},
		{"explicitly enabled", &trueVal, true},
		{"explicitly disabled", &falseVal, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Rule{Enabled: tt.enabled}
			if got := r.IsEnabled(); got != tt.want {
				t.Errorf("Rule.IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecisionPriority(t *testing.T) {
	// Deny should have highest priority
	if DecisionPriority(DecisionDeny) <= DecisionPriority(DecisionAsk) {
		t.Error("DENY should have higher priority than ASK")
	}
	if DecisionPriority(DecisionAsk) <= DecisionPriority(DecisionAllow) {
		t.Error("ASK should have higher priority than ALLOW")
	}
	if DecisionPriority(DecisionAllow) <= 0 {
		t.Error("ALLOW should have positive priority")
	}
}
