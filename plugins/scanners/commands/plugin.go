// Package commands provides a command scanner plugin for NinjaShield.
package commands

import (
	"context"
	"fmt"
	"time"

	"github.com/brad07/ninjashield/pkg/plugin"
	"github.com/brad07/ninjashield/pkg/scanners"
)

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "scanner:commands"

	// PluginVersion is the current version of this plugin.
	PluginVersion = "1.0.0"

	// DefaultPriority is the default execution priority.
	DefaultPriority = 95
)

// Config holds configuration for the command scanner plugin.
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

// CommandScanner is a plugin wrapper for the command scanner.
type CommandScanner struct {
	scanner *scanners.CommandScanner
	config  Config
}

// New creates a new CommandScanner plugin.
func New() plugin.ScannerPlugin {
	return &CommandScanner{
		config: DefaultConfig(),
	}
}

// Info returns metadata about the plugin.
func (s *CommandScanner) Info() plugin.PluginInfo {
	return plugin.PluginInfo{
		ID:          PluginID,
		Name:        "Command Scanner",
		Version:     PluginVersion,
		Type:        plugin.PluginTypeScanner,
		Tier:        plugin.TierCompileTime,
		Description: "Detects dangerous command patterns including remote code execution, destructive operations, and privilege escalation.",
		Author:      "NinjaShield",
		Capabilities: []string{
			"remote_code_execution",
			"destructive_commands",
			"privilege_escalation",
			"network_operations",
			"sensitive_access",
			"obfuscation",
		},
	}
}

// Init initializes the plugin with configuration.
func (s *CommandScanner) Init(ctx context.Context, config map[string]any) error {
	if priority, ok := config["priority"].(int); ok {
		s.config.Priority = priority
	}
	if enabled, ok := config["enabled"].(bool); ok {
		s.config.Enabled = enabled
	}

	s.scanner = scanners.NewCommandScanner()

	return nil
}

// Shutdown gracefully stops the plugin.
func (s *CommandScanner) Shutdown(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the plugin is functioning correctly.
func (s *CommandScanner) HealthCheck(ctx context.Context) error {
	_ = s.scanner.Scan("test")
	return nil
}

// Scan performs content analysis and returns findings.
func (s *CommandScanner) Scan(ctx context.Context, req *plugin.ScanRequest) (*plugin.ScanResponse, error) {
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

	// Also get detailed command analysis for additional metadata
	var metadata map[string]any
	if req.ContentType == "command" {
		info := s.scanner.AnalyzeCommand(req.Content)
		metadata = map[string]any{
			"executable":     info.Executable,
			"flags":          info.Flags,
			"has_pipe":       info.HasPipe,
			"has_redirect":   info.HasRedirect,
			"has_background": info.HasBackground,
			"categories":     info.Categories,
		}
	}

	return &plugin.ScanResponse{
		RequestID:        req.ID,
		PluginID:         PluginID,
		Findings:         findings,
		RiskScore:        result.RiskScore,
		Summary:          formatSummary(findings),
		ProcessingTimeMs: time.Since(start).Milliseconds(),
		Metadata:         metadata,
	}, nil
}

// Priority returns the execution priority.
func (s *CommandScanner) Priority() int {
	return s.config.Priority
}

// SupportedContentTypes returns the content types this scanner can process.
func (s *CommandScanner) SupportedContentTypes() []string {
	return []string{"command", "shell", "bash", "script"}
}

// formatSummary creates a human-readable summary of findings.
func formatSummary(findings []scanners.Finding) string {
	if len(findings) == 0 {
		return "No dangerous patterns detected"
	}

	categoryCount := make(map[string]int)
	for _, f := range findings {
		categoryCount[f.Category]++
	}

	if len(categoryCount) == 1 {
		for cat, c := range categoryCount {
			return fmt.Sprintf("%d %s pattern(s) detected", c, cat)
		}
	}

	return fmt.Sprintf("%d dangerous patterns detected across %d categories", len(findings), len(categoryCount))
}

// init registers the plugin with the global registry.
func init() {
	plugin.RegisterScanner("commands", New)
}
