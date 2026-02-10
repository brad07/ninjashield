package plugin

import (
	"context"

	"github.com/brad07/ninjashield/pkg/scanners"
)

// ScanRequest represents a request to scan content.
type ScanRequest struct {
	// ID is a unique identifier for this scan request.
	ID string `json:"id"`

	// Content is the raw content to scan.
	Content string `json:"content"`

	// ContentType hints at the type of content (e.g., "command", "file", "message").
	ContentType string `json:"content_type"`

	// Context provides additional context about the scan.
	Context ScanContext `json:"context,omitempty"`

	// Options contains scanner-specific options.
	Options map[string]any `json:"options,omitempty"`
}

// ScanContext provides contextual information for a scan.
type ScanContext struct {
	// Source indicates where the content originated (e.g., "claude-code", "vscode").
	Source string `json:"source,omitempty"`

	// User is the user or process that initiated the scan.
	User string `json:"user,omitempty"`

	// WorkingDirectory is the current working directory, if applicable.
	WorkingDirectory string `json:"working_directory,omitempty"`

	// FilePath is the path to the file being scanned, if applicable.
	FilePath string `json:"file_path,omitempty"`

	// SessionID links related scans together.
	SessionID string `json:"session_id,omitempty"`

	// Metadata contains additional context-specific data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ScanResponse represents the result of a scan operation.
type ScanResponse struct {
	// RequestID matches the request ID for correlation.
	RequestID string `json:"request_id"`

	// PluginID identifies which scanner produced this response.
	PluginID string `json:"plugin_id"`

	// Findings contains all detected issues.
	Findings []scanners.Finding `json:"findings"`

	// RiskScore is the aggregated risk score (0-100).
	RiskScore int `json:"risk_score"`

	// Summary provides a human-readable summary of the scan results.
	Summary string `json:"summary,omitempty"`

	// ProcessingTimeMs is how long the scan took in milliseconds.
	ProcessingTimeMs int64 `json:"processing_time_ms"`

	// Error contains any error message if the scan failed.
	Error string `json:"error,omitempty"`

	// Metadata contains additional scanner-specific data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// ScannerPlugin is the interface for scanner plugins.
type ScannerPlugin interface {
	Plugin

	// Scan performs content analysis and returns findings.
	Scan(ctx context.Context, req *ScanRequest) (*ScanResponse, error)

	// Priority returns the execution priority (higher = earlier).
	// Scanners with higher priority are executed first.
	Priority() int

	// SupportedContentTypes returns the content types this scanner can process.
	// An empty slice means all content types are supported.
	SupportedContentTypes() []string
}

// ScannerFactory is a function that creates a new ScannerPlugin instance.
type ScannerFactory func() ScannerPlugin

// AggregatedScanResponse combines results from multiple scanners.
type AggregatedScanResponse struct {
	// RequestID is the original request ID.
	RequestID string `json:"request_id"`

	// Responses contains individual scanner responses.
	Responses []*ScanResponse `json:"responses"`

	// AllFindings contains all findings from all scanners.
	AllFindings []scanners.Finding `json:"all_findings"`

	// AggregatedRiskScore is the combined risk score (0-100).
	AggregatedRiskScore int `json:"aggregated_risk_score"`

	// HighestSeverity is the most severe finding level (e.g., "critical", "high", "medium", "low").
	HighestSeverity string `json:"highest_severity"`

	// TotalProcessingTimeMs is the total processing time.
	TotalProcessingTimeMs int64 `json:"total_processing_time_ms"`

	// ScannersUsed lists the plugin IDs of scanners that contributed.
	ScannersUsed []string `json:"scanners_used"`

	// ContentClasses are derived classifications from findings.
	ContentClasses []string `json:"content_classes"`
}

// AggregateScanResponses combines multiple scan responses into one.
func AggregateScanResponses(requestID string, responses []*ScanResponse) *AggregatedScanResponse {
	agg := &AggregatedScanResponse{
		RequestID:      requestID,
		Responses:      responses,
		AllFindings:    make([]scanners.Finding, 0),
		ScannersUsed:   make([]string, 0, len(responses)),
		ContentClasses: make([]string, 0),
	}

	classSet := make(map[string]struct{})
	var maxSeverity string

	for _, resp := range responses {
		if resp == nil {
			continue
		}

		agg.ScannersUsed = append(agg.ScannersUsed, resp.PluginID)
		agg.TotalProcessingTimeMs += resp.ProcessingTimeMs
		agg.AllFindings = append(agg.AllFindings, resp.Findings...)

		// Track highest risk score
		if resp.RiskScore > agg.AggregatedRiskScore {
			agg.AggregatedRiskScore = resp.RiskScore
		}

		// Track highest severity and content classes
		for _, f := range resp.Findings {
			if severityRank(f.Severity) > severityRank(maxSeverity) {
				maxSeverity = f.Severity
			}
			classSet[f.Category] = struct{}{}
		}
	}

	agg.HighestSeverity = maxSeverity

	for class := range classSet {
		agg.ContentClasses = append(agg.ContentClasses, class)
	}

	return agg
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
