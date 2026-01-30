// Package packs provides embedded default policy packs for NinjaShield.
package packs

import (
	"embed"
	"fmt"

	"github.com/brad07/ninjashield/pkg/policy"
)

//go:embed *.yaml
var packsFS embed.FS

// PackName represents a policy pack name.
type PackName string

const (
	Conservative      PackName = "conservative"
	Balanced          PackName = "balanced"
	DeveloperFriendly PackName = "developer-friendly"
)

// ValidPackNames returns all valid pack names.
func ValidPackNames() []PackName {
	return []PackName{Conservative, Balanced, DeveloperFriendly}
}

// IsValidPackName checks if a pack name is valid.
func IsValidPackName(name string) bool {
	for _, valid := range ValidPackNames() {
		if string(valid) == name {
			return true
		}
	}
	return false
}

// Load loads a policy pack by name.
func Load(name PackName) (*policy.Policy, error) {
	filename := string(name) + ".yaml"
	data, err := packsFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read pack %s: %w", name, err)
	}

	return policy.Parse(data)
}

// LoadByName loads a policy pack by string name.
func LoadByName(name string) (*policy.Policy, error) {
	if !IsValidPackName(name) {
		return nil, fmt.Errorf("invalid pack name: %s (valid: conservative, balanced, developer-friendly)", name)
	}
	return Load(PackName(name))
}

// LoadAll loads all available policy packs.
func LoadAll() (map[PackName]*policy.Policy, error) {
	packs := make(map[PackName]*policy.Policy)

	for _, name := range ValidPackNames() {
		p, err := Load(name)
		if err != nil {
			return nil, fmt.Errorf("failed to load pack %s: %w", name, err)
		}
		packs[name] = p
	}

	return packs, nil
}

// MustLoad loads a policy pack and panics on error.
// Useful for initialization where failure should be fatal.
func MustLoad(name PackName) *policy.Policy {
	p, err := Load(name)
	if err != nil {
		panic(fmt.Sprintf("failed to load required policy pack %s: %v", name, err))
	}
	return p
}

// Default returns the default policy pack (balanced).
func Default() (*policy.Policy, error) {
	return Load(Balanced)
}

// MustDefault returns the default policy pack and panics on error.
func MustDefault() *policy.Policy {
	return MustLoad(Balanced)
}

// Description returns a human-readable description of a pack.
func Description(name PackName) string {
	switch name {
	case Conservative:
		return "Maximum security - requires approval for most operations. Only safe read-only commands are auto-approved."
	case Balanced:
		return "Good security with developer productivity. Auto-approves common safe commands, requires approval for risky operations."
	case DeveloperFriendly:
		return "Maximum productivity with essential safety guardrails. Blocks only clearly dangerous operations."
	default:
		return "Unknown policy pack"
	}
}

// PackInfo contains information about a policy pack.
type PackInfo struct {
	Name        PackName
	DisplayName string
	Description string
	RuleCount   int
}

// Info returns information about a policy pack.
func Info(name PackName) (*PackInfo, error) {
	p, err := Load(name)
	if err != nil {
		return nil, err
	}

	return &PackInfo{
		Name:        name,
		DisplayName: p.Name,
		Description: Description(name),
		RuleCount:   len(p.Rules),
	}, nil
}

// ListAll returns information about all available packs.
func ListAll() ([]*PackInfo, error) {
	var infos []*PackInfo

	for _, name := range ValidPackNames() {
		info, err := Info(name)
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}

	return infos, nil
}
