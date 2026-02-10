// Package ollama provides an Ollama LLM provider plugin for NinjaShield.
package ollama

import (
	"context"
	"time"

	"github.com/brad07/ninjashield/pkg/localllm"
	"github.com/brad07/ninjashield/pkg/plugin"
)

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "llm:ollama"

	// PluginVersion is the current version of this plugin.
	PluginVersion = "1.0.0"

	// DefaultEndpoint is the default Ollama API endpoint.
	DefaultEndpoint = "http://localhost:11434"

	// DefaultModel is the default model to use.
	DefaultModel = "gemma3"
)

// Config holds configuration for the Ollama provider plugin.
type Config struct {
	// Enabled determines if the provider is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Endpoint is the Ollama API endpoint.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Model is the model to use for assessments.
	Model string `yaml:"model" json:"model"`

	// Mode is the scoring mode (fast/strict).
	Mode string `yaml:"mode" json:"mode"`
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:  true,
		Endpoint: DefaultEndpoint,
		Model:    DefaultModel,
		Mode:     "fast",
	}
}

// OllamaProvider is a plugin wrapper for the Ollama LLM provider.
type OllamaProvider struct {
	provider *localllm.OllamaProvider
	config   Config
}

// New creates a new OllamaProvider plugin.
func New() plugin.LLMProviderPlugin {
	return &OllamaProvider{
		config: DefaultConfig(),
	}
}

// Info returns metadata about the plugin.
func (p *OllamaProvider) Info() plugin.PluginInfo {
	return plugin.PluginInfo{
		ID:          PluginID,
		Name:        "Ollama Provider",
		Version:     PluginVersion,
		Type:        plugin.PluginTypeLLMProvider,
		Tier:        plugin.TierCompileTime,
		Description: "Local LLM provider using Ollama for AI-based risk assessment.",
		Author:      "NinjaShield",
		Homepage:    "https://ollama.ai",
		Capabilities: []string{
			"command_assessment",
			"content_assessment",
			"json_output",
		},
	}
}

// Init initializes the plugin with configuration.
func (p *OllamaProvider) Init(ctx context.Context, config map[string]any) error {
	// Apply configuration if provided
	if enabled, ok := config["enabled"].(bool); ok {
		p.config.Enabled = enabled
	}
	if endpoint, ok := config["endpoint"].(string); ok && endpoint != "" {
		p.config.Endpoint = endpoint
	}
	if model, ok := config["model"].(string); ok && model != "" {
		p.config.Model = model
	}
	if mode, ok := config["mode"].(string); ok && mode != "" {
		p.config.Mode = mode
	}

	// Create the underlying provider
	llmConfig := localllm.Config{
		Type:     localllm.ProviderOllama,
		Endpoint: p.config.Endpoint,
		Model:    p.config.Model,
		Mode:     localllm.Mode(p.config.Mode),
	}

	provider, err := localllm.NewOllamaProvider(llmConfig)
	if err != nil {
		return err
	}

	p.provider = provider
	return nil
}

// Shutdown gracefully stops the plugin.
func (p *OllamaProvider) Shutdown(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the plugin is functioning correctly.
func (p *OllamaProvider) HealthCheck(ctx context.Context) error {
	if !p.provider.IsAvailable(ctx) {
		return plugin.ErrProviderUnavailable
	}
	return nil
}

// IsAvailable checks if the provider is ready to accept requests.
func (p *OllamaProvider) IsAvailable(ctx context.Context) bool {
	if !p.config.Enabled || p.provider == nil {
		return false
	}
	return p.provider.IsAvailable(ctx)
}

// AssessCommand evaluates the risk of a command.
func (p *OllamaProvider) AssessCommand(ctx context.Context, req *plugin.CommandAssessmentRequest) (*plugin.RiskAssessment, error) {
	start := time.Now()

	// Convert to localllm format
	summary := localllm.CommandSummary{
		Command: req.Command,
		Cwd:     req.Context.WorkingDirectory,
		User:    req.Context.User,
		Tool:    req.Context.Source,
	}

	// Include scan results if available
	if req.ScanResults != nil {
		summary.InitialScore = req.ScanResults.AggregatedRiskScore
		for _, class := range req.ScanResults.ContentClasses {
			summary.DetectedRisks = append(summary.DetectedRisks, class)
		}
	}

	// Call the underlying provider
	assessment, err := p.provider.AssessCommand(ctx, summary)
	if err != nil {
		return nil, err
	}

	return &plugin.RiskAssessment{
		RequestID:        req.ID,
		PluginID:         PluginID,
		Score:            assessment.RiskScore,
		Categories:       assessment.RiskCategories,
		Recommendation:   mapRecommendation(assessment.RecommendedAction),
		Explanation:      assessment.Explanation,
		Confidence:       assessment.Confidence,
		ProcessingTimeMs: time.Since(start).Milliseconds(),
	}, nil
}

// AssessContent evaluates the risk of arbitrary content.
func (p *OllamaProvider) AssessContent(ctx context.Context, req *plugin.ContentAssessmentRequest) (*plugin.RiskAssessment, error) {
	start := time.Now()

	// Convert to localllm format
	summary := localllm.ContentSummary{
		RequestType:    req.ContentType,
		ContentPreview: truncate(req.Content, 500),
	}

	if req.Context.Source != "" {
		summary.Provider = req.Context.Source
	}

	// Include scan results if available
	if req.ScanResults != nil {
		summary.ContentClasses = req.ScanResults.ContentClasses
		// Count findings by category
		for _, f := range req.ScanResults.AllFindings {
			if f.Category == "secrets" {
				summary.DetectedSecrets++
			} else if f.Category == "pii" {
				summary.DetectedPII++
			}
		}
	}

	assessment, err := p.provider.AssessContent(ctx, summary)
	if err != nil {
		return nil, err
	}

	return &plugin.RiskAssessment{
		RequestID:        req.ID,
		PluginID:         PluginID,
		Score:            assessment.RiskScore,
		Categories:       assessment.RiskCategories,
		Recommendation:   mapRecommendation(assessment.RecommendedAction),
		Explanation:      assessment.Explanation,
		Confidence:       assessment.Confidence,
		ProcessingTimeMs: time.Since(start).Milliseconds(),
	}, nil
}

// SupportsStreaming returns true if the provider supports streaming responses.
func (p *OllamaProvider) SupportsStreaming() bool {
	return false
}

// ModelInfo returns information about the currently configured model.
func (p *OllamaProvider) ModelInfo() plugin.ModelInfo {
	return plugin.ModelInfo{
		Name:     p.config.Model,
		Provider: "ollama",
		Capabilities: []string{
			"text_generation",
			"json_output",
		},
	}
}

// mapRecommendation converts a string recommendation to plugin.Recommendation.
func mapRecommendation(action string) plugin.Recommendation {
	switch action {
	case "allow":
		return plugin.RecommendationAllow
	case "deny":
		return plugin.RecommendationDeny
	case "ask":
		return plugin.RecommendationAsk
	case "redact":
		return plugin.RecommendationRedact
	case "modify":
		return plugin.RecommendationModify
	case "monitor":
		return plugin.RecommendationMonitor
	default:
		return plugin.RecommendationAsk
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// init registers the plugin with the global registry.
func init() {
	plugin.RegisterLLMProvider("ollama", New)
}
