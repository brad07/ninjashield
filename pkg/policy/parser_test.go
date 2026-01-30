package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse(t *testing.T) {
	validYAML := `
id: test-policy
name: Test Policy
version: "1.0.0"
description: A test policy
default_action:
  decision: ASK
  reason: Default requires approval
rules:
  - id: allow-ls
    name: Allow ls command
    priority: 10
    conditions:
      - type: command_prefix
        pattern: ls
    action:
      decision: ALLOW
      reason: Safe read-only command
  - id: block-rm-rf
    name: Block rm -rf
    priority: 100
    risk_category: destructive
    risk_score: 90
    conditions:
      - type: command_prefix
        pattern: rm
      - type: has_flag
        pattern: "-rf"
    action:
      decision: DENY
      reason: Destructive command blocked
      reason_code: DESTRUCTIVE_DELETE
`

	policy, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if policy.ID != "test-policy" {
		t.Errorf("ID = %v, want test-policy", policy.ID)
	}
	if policy.Name != "Test Policy" {
		t.Errorf("Name = %v, want Test Policy", policy.Name)
	}
	if policy.Version != "1.0.0" {
		t.Errorf("Version = %v, want 1.0.0", policy.Version)
	}
	if len(policy.Rules) != 2 {
		t.Errorf("len(Rules) = %v, want 2", len(policy.Rules))
	}

	// Rules should be sorted by priority (higher first)
	if policy.Rules[0].ID != "block-rm-rf" {
		t.Errorf("First rule should be block-rm-rf (priority 100), got %s", policy.Rules[0].ID)
	}
	if policy.Rules[1].ID != "allow-ls" {
		t.Errorf("Second rule should be allow-ls (priority 10), got %s", policy.Rules[1].ID)
	}
}

func TestParseInvalid(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{
			name: "invalid yaml",
			yaml: "not: valid: yaml: [",
		},
		{
			name: "missing required fields",
			yaml: `
name: Test
version: "1.0.0"
`,
		},
		{
			name: "invalid rule",
			yaml: `
id: test
name: Test
version: "1.0.0"
default_action:
  decision: ASK
  reason: Default
rules:
  - id: bad-rule
    name: Bad Rule
    conditions: []
    action:
      decision: ALLOW
      reason: Allow
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Error("Parse() expected error, got nil")
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "ninjashield-policy-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Write test policy file
	policyContent := `
id: file-test
name: File Test Policy
version: "1.0.0"
default_action:
  decision: LOG_ONLY
  reason: Log everything
rules:
  - id: test-rule
    name: Test Rule
    conditions:
      - type: command_prefix
        pattern: echo
    action:
      decision: ALLOW
      reason: Safe
`
	policyPath := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0600); err != nil {
		t.Fatal(err)
	}

	policy, err := LoadFromFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if policy.ID != "file-test" {
		t.Errorf("ID = %v, want file-test", policy.ID)
	}
}

func TestLoadFromFileNotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/policy.yaml")
	if err == nil {
		t.Error("LoadFromFile() expected error for nonexistent file")
	}
}

func TestSaveToFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "ninjashield-policy-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	policy := &Policy{
		ID:      "save-test",
		Name:    "Save Test Policy",
		Version: "1.0.0",
		DefaultAction: Action{
			Decision: DecisionAsk,
			Reason:   "Default",
		},
		Rules: []Rule{
			{
				ID:   "test-rule",
				Name: "Test Rule",
				Conditions: []Condition{
					{Type: ConditionCommandPrefix, Pattern: "test"},
				},
				Action: Action{Decision: DecisionAllow, Reason: "Allow"},
			},
		},
	}

	policyPath := filepath.Join(tmpDir, "saved-policy.yaml")
	if err := policy.SaveToFile(policyPath); err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Load it back
	loaded, err := LoadFromFile(policyPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if loaded.ID != policy.ID {
		t.Errorf("ID = %v, want %v", loaded.ID, policy.ID)
	}
	if loaded.Name != policy.Name {
		t.Errorf("Name = %v, want %v", loaded.Name, policy.Name)
	}
}

func TestMergePolicies(t *testing.T) {
	base := &Policy{
		ID:      "base",
		Name:    "Base Policy",
		Version: "1.0.0",
		DefaultAction: Action{
			Decision: DecisionAsk,
			Reason:   "Base default",
		},
		Rules: []Rule{
			{
				ID:       "rule1",
				Name:     "Rule 1",
				Priority: 10,
				Conditions: []Condition{
					{Type: ConditionCommandPrefix, Pattern: "ls"},
				},
				Action: Action{Decision: DecisionAllow, Reason: "Allow ls"},
			},
		},
	}

	override := &Policy{
		ID:      "override",
		Name:    "Override Policy",
		Version: "2.0.0",
		DefaultAction: Action{
			Decision: DecisionDeny,
			Reason:   "Override default",
		},
		Rules: []Rule{
			{
				ID:       "rule1", // Override existing rule
				Name:     "Rule 1 Override",
				Priority: 20,
				Conditions: []Condition{
					{Type: ConditionCommandPrefix, Pattern: "ls"},
				},
				Action: Action{Decision: DecisionLogOnly, Reason: "Log ls"},
			},
			{
				ID:       "rule2", // New rule
				Name:     "Rule 2",
				Priority: 5,
				Conditions: []Condition{
					{Type: ConditionCommandPrefix, Pattern: "cat"},
				},
				Action: Action{Decision: DecisionAllow, Reason: "Allow cat"},
			},
		},
	}

	merged, err := MergePolicies(base, override)
	if err != nil {
		t.Fatalf("MergePolicies() error = %v", err)
	}

	// Should have override's metadata
	if merged.ID != "override" {
		t.Errorf("ID = %v, want override", merged.ID)
	}
	if merged.Version != "2.0.0" {
		t.Errorf("Version = %v, want 2.0.0", merged.Version)
	}
	if merged.DefaultAction.Decision != DecisionDeny {
		t.Errorf("DefaultAction.Decision = %v, want DENY", merged.DefaultAction.Decision)
	}

	// Should have 2 rules (rule1 overridden, rule2 added)
	if len(merged.Rules) != 2 {
		t.Errorf("len(Rules) = %v, want 2", len(merged.Rules))
	}

	// Rules should be sorted by priority
	if merged.Rules[0].Priority != 20 {
		t.Errorf("First rule priority = %v, want 20", merged.Rules[0].Priority)
	}

	// rule1 should have override's action
	for _, r := range merged.Rules {
		if r.ID == "rule1" {
			if r.Action.Decision != DecisionLogOnly {
				t.Errorf("rule1 action = %v, want LOG_ONLY", r.Action.Decision)
			}
		}
	}
}

func TestMergePoliciesEmpty(t *testing.T) {
	_, err := MergePolicies()
	if err == nil {
		t.Error("MergePolicies() expected error for empty input")
	}
}
