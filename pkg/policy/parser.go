package policy

import (
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

// LoadFromFile loads a policy from a YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	return Parse(data)
}

// Parse parses a policy from YAML bytes.
func Parse(data []byte) (*Policy, error) {
	var policy Policy
	if err := yaml.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	// Sort rules by priority (higher first)
	sort.SliceStable(policy.Rules, func(i, j int) bool {
		return policy.Rules[i].Priority > policy.Rules[j].Priority
	})

	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	return &policy, nil
}

// SaveToFile saves a policy to a YAML file.
func (p *Policy) SaveToFile(path string) error {
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	header := []byte("# NinjaShield Policy Configuration\n\n")
	data = append(header, data...)

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	return nil
}

// MergePolicies merges multiple policies, with later policies taking precedence.
// Rules are combined and re-sorted by priority.
func MergePolicies(policies ...*Policy) (*Policy, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("no policies to merge")
	}

	// Start with the first policy as the base
	merged := &Policy{
		ID:            policies[0].ID,
		Name:          policies[0].Name,
		Version:       policies[0].Version,
		Description:   policies[0].Description,
		DefaultAction: policies[0].DefaultAction,
		Rules:         make([]Rule, 0),
	}

	// Track rule IDs to handle overrides
	rulesByID := make(map[string]Rule)

	for _, p := range policies {
		// Later policies override metadata
		if p.ID != "" {
			merged.ID = p.ID
		}
		if p.Name != "" {
			merged.Name = p.Name
		}
		if p.Version != "" {
			merged.Version = p.Version
		}
		if p.Description != "" {
			merged.Description = p.Description
		}
		if p.DefaultAction.Decision != "" {
			merged.DefaultAction = p.DefaultAction
		}

		// Merge rules - later rules with same ID override earlier ones
		for _, rule := range p.Rules {
			if rule.ID != "" {
				rulesByID[rule.ID] = rule
			} else {
				// Rules without ID are always added
				merged.Rules = append(merged.Rules, rule)
			}
		}
	}

	// Add rules from map
	for _, rule := range rulesByID {
		merged.Rules = append(merged.Rules, rule)
	}

	// Sort by priority
	sort.SliceStable(merged.Rules, func(i, j int) bool {
		return merged.Rules[i].Priority > merged.Rules[j].Priority
	})

	return merged, nil
}
