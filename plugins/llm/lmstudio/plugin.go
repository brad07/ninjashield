// Package lmstudio provides an LM Studio LLM provider plugin for NinjaShield.
package lmstudio

import (
	"context"
	"time"

	"github.com/brad07/ninjashield/pkg/localllm"
	"github.com/brad07/ninjashield/pkg/plugin"
)

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "llm:lmstudio"

	// PluginVersion is the current version of this plugin.
	PluginVersion = "1.0.0"

	// DefaultEndpoint is the default LM Studio API endpoint.
	DefaultEndpoint = "http://localhost:1234"

	// DefaultModel is the default model to use.
	DefaultModel = "local-model"
)

// Config holds configuration for the LM Studio provider plugin.
type Config struct {
	// Enabled determines if the provider is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Endpoint is the LM Studio API endpoint.
	Endpoint string `yaml:"endpoint" json:"endpoint"`

	// Model is the model to use for assessments.
	Model string `yaml:"model" json:"model"`

	// Mode is the scoring mode (fast/strict).
	Mode string `yaml:"mode" json:"mode"`

	// APIKey is an optional API key.
	APIKey string `yaml:"api_key" json:"api_key"`
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

// LMStudioProvider is a plugin wrapper for the LM Studio LLM provider.
type LMStudioProvider struct {
	provider *localllm.LMStudioProvider
	config   Config
}

// New creates a new LMStudioProvider plugin.
func New() plugin.LLMProviderPlugin {
	return &LMStudioProvider{
		config: DefaultConfig(),
	}
}

// Info returns metadata about the plugin.
func (p *LMStudioProvider) Info() plugin.PluginInfo {
	return plugin.PluginInfo{
		ID:          PluginID,
		Name:        "LM Studio Provider",
		Version:     PluginVersion,
		Type:        plugin.PluginTypeLLMProvider,
		Tier:        plugin.TierCompileTime,
		Description: "Local LLM provider using LM Studio (OpenAI-compatible API) for AI-based risk assessment.",
		Author:      "NinjaShield",
		Homepage:    "https://lmstudio.ai",
		Capabilities: []string{
			"command_assessment",
			"content_assessment",
			"openai_compatible",
			"json_output",
		},
	}
}

// Init initializes the plugin with configuration.
func (p *LMStudioProvider) Init(ctx context.Context, config map[string]any) error {
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
	if apiKey, ok := config["api_key"].(string); ok {
		p.config.APIKey = apiKey
	}

	// Create the underlying provider
	llmConfig := localllm.Config{
		Type:     localllm.ProviderLMStudio,
		Endpoint: p.config.Endpoint,
		Model:    p.config.Model,
		Mode:     localllm.Mode(p.config.Mode),
		APIKey:   p.config.APIKey,
	}

	provider, err := localllm.NewLMStudioProvider(llmConfig)
	if err != nil {
		return err
	}

	p.provider = provider
	return nil
}

// Shutdown gracefully stops the plugin.
func (p *LMStudioProvider) Shutdown(ctx context.Context) error {
	return nil
}

// HealthCheck verifies the plugin is functioning correctly.
func (p *LMStudioProvider) HealthCheck(ctx context.Context) error {
	if !p.provider.IsAvailable(ctx) {
		return plugin.ErrProviderUnavailable
	}
	return nil
}

// IsAvailable checks if the provider is ready to accept requests.
func (p *LMStudioProvider) IsAvailable(ctx context.Context) bool {
	if !p.config.Enabled || p.provider == nil {
		return false
	}
	return p.provider.IsAvailable(ctx)
}

// AssessCommand evaluates the risk of a command.
func (p *LMStudioProvider) AssessCommand(ctx context.Context, req *plugin.CommandAssessmentRequest) (*plugin.RiskAssessment, error) {
	start := time.Now()

	summary := localllm.CommandSummary{
		Command: req.Command,
		Cwd:     req.Context.WorkingDirectory,
		User:    req.Context.User,
		Tool:    req.Context.Source,
	}

	if req.ScanResults != nil {
		summary.InitialScore = req.ScanResults.AggregatedRiskScore
		for _, class := range req.ScanResults.ContentClasses {
			summary.DetectedRisks = append(summary.DetectedRisks, class)
		}
	}

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
func (p *LMStudioProvider) AssessContent(ctx context.Context, req *plugin.ContentAssessmentRequest) (*plugin.RiskAssessment, error) {
	start := time.Now()

	summary := localllm.ContentSummary{
		RequestType:    req.ContentType,
		ContentPreview: truncate(req.Content, 500),
	}

	if req.Context.Source != "" {
		summary.Provider = req.Context.Source
	}

	if req.ScanResults != nil {
		summary.ContentClasses = req.ScanResults.ContentClasses
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
func (p *LMStudioProvider) SupportsStreaming() bool {
	return false
}

// ModelInfo returns information about the currently configured model.
func (p *LMStudioProvider) ModelInfo() plugin.ModelInfo {
	return plugin.ModelInfo{
		Name:     p.config.Model,
		Provider: "lmstudio",
		Capabilities: []string{
			"text_generation",
			"openai_compatible",
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
	plugin.RegisterLLMProvider("lmstudio", New)
}
