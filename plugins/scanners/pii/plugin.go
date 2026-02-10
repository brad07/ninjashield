// Package pii provides a PII scanner plugin for NinjaShield.
package pii

import (
	"context"
	"fmt"
	"time"

	"github.com/brad07/ninjashield/pkg/plugin"
	"github.com/brad07/ninjashield/pkg/scanners"
)

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "scanner:pii"

	// PluginVersion is the current version of this plugin.
	PluginVersion = "1.0.0"

	// DefaultPriority is the default execution priority.
	DefaultPriority = 90
)

// Config holds configuration for the PII scanner plugin.
type Config struct {
	// Priority is the execution priority (higher = earlier).
	Priority int `yaml:"priority" json:"priority"`

	// Enabled determines if the scanner is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// PIIConfig holds specific PII detection settings.
	DetectEmails      bool `yaml:"detect_emails" json:"detect_emails"`
	DetectPhones      bool `yaml:"detect_phones" json:"detect_phones"`
	DetectSSN         bool `yaml:"detect_ssn" json:"detect_ssn"`
	DetectCreditCards bool `yaml:"detect_credit_cards" json:"detect_credit_cards"`
	DetectIPAddresses bool `yaml:"detect_ip_addresses" json:"detect_ip_addresses"`
	DetectAddresses   bool `yaml:"detect_addresses" json:"detect_addresses"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Priority:          DefaultPriority,
		Enabled:           true,
		DetectEmails:      true,
		DetectPhones:      true,
		DetectSSN:         true,
		DetectCreditCards: true,
		DetectIPAddresses: true,
		DetectAddresses:   false, // More false positives
	}
}

// PIIScanner is a plugin wrapper for the PII scanner.
type PIIScanner struct {
	scanner *scanners.PIIScanner
	config  Config
}

// New creates a new PIIScanner plugin.
func New() plugin.ScannerPlugin {
	return &PIIScanner{
		config: DefaultConfig(),
	}
}

// Info returns metadata about the plugin.
func (s *PIIScanner) Info() plugin.PluginInfo {
	return plugin.PluginInfo{
		ID:          PluginID,
		Name:        "PII Scanner",
		Version:     PluginVersion,
		Type:        plugin.PluginTypeScanner,
		Tier:        plugin.TierCompileTime,
		Description: "Detects personally identifiable information (PII) in content.",
		Author:      "NinjaShield",
		Capabilities: []string{
			"emails",
			"phone_numbers",
			"ssn",
			"credit_cards",
			"ip_addresses",
			"addresses",
		},
	}
}

// Init initializes the plugin with configuration.
func (s *PIIScanner) Init(ctx context.Context, config map[string]any) error {
	// Apply configuration if provided
	if priority, ok := config["priority"].(int); ok {
		s.config.Priority = priority
	}
	if enabled, ok := config["enabled"].(bool); ok {
		s.config.Enabled = enabled
	}
	if detectEmails, ok := config["detect_emails"].(bool); ok {
		s.config.DetectEmails = detectEmails
	}
	if detectPhones, ok := config["detect_phones"].(bool); ok {
		s.config.DetectPhones = detectPhones
	}
	if detectSSN, ok := config["detect_ssn"].(bool); ok {
		s.config.DetectSSN = detectSSN
	}
	if detectCreditCards, ok := config["detect_credit_cards"].(bool); ok {
		s.config.DetectCreditCards = detectCreditCards
	}
	if detectIPAddresses, ok := config["detect_ip_addresses"].(bool); ok {
		s.config.DetectIPAddresses = detectIPAddresses
	}
	if detectAddresses, ok := config["detect_addresses"].(bool); ok {
		s.config.DetectAddresses = detectAddresses
	}

	// Create the underlying scanner with custom config
	piiConfig := scanners.PIIConfig{
		DetectEmails:      s.config.DetectEmails,
		DetectPhones:      s.config.DetectPhones,
		DetectSSN:         s.config.DetectSSN,
		DetectCreditCards: s.config.DetectCreditCards,
		DetectIPAddresses: s.config.DetectIPAddresses,
		DetectAddresses:   s.config.DetectAddresses,
	}
	s.scanner = scanners.NewPIIScannerWithConfig(piiConfig)

	return nil
}

// Shutdown gracefully stops the plugin.
func (s *PIIScanner) Shutdown(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the plugin is functioning correctly.
func (s *PIIScanner) HealthCheck(ctx context.Context) error {
	_ = s.scanner.Scan("test")
	return nil
}

// Scan performs content analysis and returns findings.
func (s *PIIScanner) Scan(ctx context.Context, req *plugin.ScanRequest) (*plugin.ScanResponse, error) {
	start := time.Now()

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

	findings := s.scanner.Scan(req.Content)
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
func (s *PIIScanner) Priority() int {
	return s.config.Priority
}

// SupportedContentTypes returns the content types this scanner can process.
func (s *PIIScanner) SupportedContentTypes() []string {
	return []string{}
}

// formatSummary creates a human-readable summary of findings.
func formatSummary(findings []scanners.Finding) string {
	if len(findings) == 0 {
		return "No PII detected"
	}

	typeCount := make(map[string]int)
	for _, f := range findings {
		typeCount[f.Type]++
	}

	if len(typeCount) == 1 {
		for t, c := range typeCount {
			return fmt.Sprintf("%d %s detected", c, t)
		}
	}

	return fmt.Sprintf("%d PII items detected", len(findings))
}

// init registers the plugin with the global registry.
func init() {
	plugin.RegisterScanner("pii", New)
}
