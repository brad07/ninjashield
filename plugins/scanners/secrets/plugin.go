// Package secrets provides a secrets scanner plugin for NinjaShield.
package secrets

import (
	"context"
	"time"

	"github.com/brad07/ninjashield/pkg/plugin"
	"github.com/brad07/ninjashield/pkg/scanners"
)

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "scanner:secrets"

	// PluginVersion is the current version of this plugin.
	PluginVersion = "1.0.0"

	// DefaultPriority is the default execution priority.
	DefaultPriority = 100
)

// Config holds configuration for the secrets scanner plugin.
type Config struct {
	// Priority is the execution priority (higher = earlier).
	Priority int `yaml:"priority" json:"priority"`

	// Enabled determines if the scanner is active.
	Enabled bool `yaml:"enabled" json:"enabled"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Priority: DefaultPriority,
		Enabled:  true,
	}
}

// SecretsScanner is a plugin wrapper for the secrets scanner.
type SecretsScanner struct {
	scanner *scanners.SecretsScanner
	config  Config
}

// New creates a new SecretsScanner plugin.
func New() plugin.ScannerPlugin {
	return &SecretsScanner{
		config: DefaultConfig(),
	}
}

// Info returns metadata about the plugin.
func (s *SecretsScanner) Info() plugin.PluginInfo {
	return plugin.PluginInfo{
		ID:          PluginID,
		Name:        "Secrets Scanner",
		Version:     PluginVersion,
		Type:        plugin.PluginTypeScanner,
		Tier:        plugin.TierCompileTime,
		Description: "Detects secrets like API keys, tokens, and private keys in content.",
		Author:      "NinjaShield",
		Capabilities: []string{
			"api_keys",
			"tokens",
			"private_keys",
			"connection_strings",
			"high_entropy",
		},
	}
}

// Init initializes the plugin with configuration.
func (s *SecretsScanner) Init(ctx context.Context, config map[string]any) error {
	// Apply configuration if provided
	if priority, ok := config["priority"].(int); ok {
		s.config.Priority = priority
	}
	if enabled, ok := config["enabled"].(bool); ok {
		s.config.Enabled = enabled
	}

	// Create the underlying scanner
	s.scanner = scanners.NewSecretsScanner()

	return nil
}

// Shutdown gracefully stops the plugin.
func (s *SecretsScanner) Shutdown(ctx context.Context) error {
	// No cleanup required for this scanner
	return nil
}

// HealthCheck verifies the plugin is functioning correctly.
func (s *SecretsScanner) HealthCheck(ctx context.Context) error {
	// Simple test scan to verify patterns are compiled
	_ = s.scanner.Scan("test")
	return nil
}

// Scan performs content analysis and returns findings.
func (s *SecretsScanner) Scan(ctx context.Context, req *plugin.ScanRequest) (*plugin.ScanResponse, error) {
	start := time.Now()

	// Check if scanner is enabled
	if !s.config.Enabled {
		return &plugin.ScanResponse{
			RequestID:        req.ID,
			PluginID:         PluginID,
			Findings:         []scanners.Finding{},
			RiskScore:        0,
			Summary:          "Scanner disabled",
			ProcessingTimeMs: time.Since(start).Milliseconds(),
		}, nil
	}

	// Run the underlying scanner
	findings := s.scanner.Scan(req.Content)

	// Calculate risk score
	result := scanners.Aggregate(findings)

	return &plugin.ScanResponse{
		RequestID:        req.ID,
		PluginID:         PluginID,
		Findings:         findings,
		RiskScore:        result.RiskScore,
		Summary:          formatSummary(findings),
		ProcessingTimeMs: time.Since(start).Milliseconds(),
	}, nil
}

// Priority returns the execution priority.
func (s *SecretsScanner) Priority() int {
	return s.config.Priority
}

// SupportedContentTypes returns the content types this scanner can process.
func (s *SecretsScanner) SupportedContentTypes() []string {
	// Supports all content types
	return []string{}
}

// formatSummary creates a human-readable summary of findings.
func formatSummary(findings []scanners.Finding) string {
	if len(findings) == 0 {
		return "No secrets detected"
	}

	typeCount := make(map[string]int)
	for _, f := range findings {
		typeCount[f.Type]++
	}

	return formatTypeCount(typeCount, "secret")
}

func formatTypeCount(counts map[string]int, category string) string {
	total := 0
	for _, count := range counts {
		total += count
	}

	if total == 1 {
		return "1 " + category + " detected"
	}
	return string(rune('0'+total%10)) + " " + category + "s detected"
}

// init registers the plugin with the global registry.
func init() {
	plugin.RegisterScanner("secrets", New)
}
