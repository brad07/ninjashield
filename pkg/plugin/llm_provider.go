package plugin

import (
	"context"
)

// Recommendation represents an AI's recommended action.
type Recommendation string

const (
	RecommendationAllow   Recommendation = "allow"
	RecommendationDeny    Recommendation = "deny"
	RecommendationAsk     Recommendation = "ask"
	RecommendationModify  Recommendation = "modify"
	RecommendationMonitor Recommendation = "monitor"
	RecommendationRedact  Recommendation = "redact"
)

// CommandAssessmentRequest represents a request to assess a command.
type CommandAssessmentRequest struct {
	// ID is a unique identifier for this assessment request.
	ID string `json:"id"`

	// Command is the command to assess.
	Command string `json:"command"`

	// Context provides contextual information about the command.
	Context CommandContext `json:"context,omitempty"`

	// ScanResults contains findings from static scanners.
	ScanResults *AggregatedScanResponse `json:"scan_results,omitempty"`

	// Options contains provider-specific options.
	Options map[string]any `json:"options,omitempty"`
}

// CommandContext provides additional context for command assessment.
type CommandContext struct {
	// WorkingDirectory is where the command would execute.
	WorkingDirectory string `json:"working_directory,omitempty"`

	// User is the user executing the command.
	User string `json:"user,omitempty"`

	// Shell is the shell being used.
	Shell string `json:"shell,omitempty"`

	// Environment contains relevant environment variables.
	Environment map[string]string `json:"environment,omitempty"`

	// RecentCommands contains recently executed commands for context.
	RecentCommands []string `json:"recent_commands,omitempty"`

	// Source indicates the integration source.
	Source string `json:"source,omitempty"`
}

// ContentAssessmentRequest represents a request to assess arbitrary content.
type ContentAssessmentRequest struct {
	// ID is a unique identifier for this assessment request.
	ID string `json:"id"`

	// Content is the content to assess.
	Content string `json:"content"`

	// ContentType describes the type of content.
	ContentType string `json:"content_type"`

	// Context provides additional context.
	Context ContentContext `json:"context,omitempty"`

	// ScanResults contains findings from static scanners.
	ScanResults *AggregatedScanResponse `json:"scan_results,omitempty"`

	// Options contains provider-specific options.
	Options map[string]any `json:"options,omitempty"`
}

// ContentContext provides additional context for content assessment.
type ContentContext struct {
	// Source indicates where the content originated.
	Source string `json:"source,omitempty"`

	// Purpose describes why the content is being assessed.
	Purpose string `json:"purpose,omitempty"`

	// Metadata contains additional context-specific data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// RiskAssessment represents an AI-generated risk assessment.
type RiskAssessment struct {
	// RequestID matches the request ID for correlation.
	RequestID string `json:"request_id"`

	// PluginID identifies which provider produced this assessment.
	PluginID string `json:"plugin_id"`

	// Score is the risk score (0-100).
	Score int `json:"score"`

	// Categories lists the risk categories identified.
	Categories []string `json:"categories"`

	// Recommendation is the suggested action.
	Recommendation Recommendation `json:"recommendation"`

	// Explanation provides reasoning for the assessment.
	Explanation string `json:"explanation"`

	// Confidence indicates how confident the model is (0.0-1.0).
	Confidence float64 `json:"confidence"`

	// ProcessingTimeMs is how long the assessment took.
	ProcessingTimeMs int64 `json:"processing_time_ms"`

	// TokensUsed is the number of tokens consumed.
	TokensUsed int `json:"tokens_used,omitempty"`

	// Error contains any error message if assessment failed.
	Error string `json:"error,omitempty"`

	// RawResponse contains the raw model response for debugging.
	RawResponse string `json:"raw_response,omitempty"`
}

// LLMProviderPlugin is the interface for LLM provider plugins.
type LLMProviderPlugin interface {
	Plugin

	// IsAvailable checks if the provider is ready to accept requests.
	IsAvailable(ctx context.Context) bool

	// AssessCommand evaluates the risk of a command.
	AssessCommand(ctx context.Context, req *CommandAssessmentRequest) (*RiskAssessment, error)

	// AssessContent evaluates the risk of arbitrary content.
	AssessContent(ctx context.Context, req *ContentAssessmentRequest) (*RiskAssessment, error)

	// SupportsStreaming returns true if the provider supports streaming responses.
	SupportsStreaming() bool

	// ModelInfo returns information about the currently configured model.
	ModelInfo() ModelInfo
}

// ModelInfo contains information about an LLM model.
type ModelInfo struct {
	// Name is the model name.
	Name string `json:"name"`

	// Provider is the model provider.
	Provider string `json:"provider"`

	// ContextWindow is the maximum context length.
	ContextWindow int `json:"context_window,omitempty"`

	// SupportsVision indicates if the model can process images.
	SupportsVision bool `json:"supports_vision,omitempty"`

	// Capabilities lists model capabilities.
	Capabilities []string `json:"capabilities,omitempty"`
}

// LLMProviderFactory is a function that creates a new LLMProviderPlugin instance.
type LLMProviderFactory func() LLMProviderPlugin

// GenerateRequest represents a generic generation request.
type GenerateRequest struct {
	// Prompt is the prompt to send to the model.
	Prompt string `json:"prompt"`

	// SystemPrompt is an optional system prompt.
	SystemPrompt string `json:"system_prompt,omitempty"`

	// MaxTokens is the maximum number of tokens to generate.
	MaxTokens int `json:"max_tokens,omitempty"`

	// Temperature controls randomness (0.0-1.0).
	Temperature float64 `json:"temperature,omitempty"`

	// Options contains additional provider-specific options.
	Options map[string]any `json:"options,omitempty"`
}

// GenerateResponse represents a generation response.
type GenerateResponse struct {
	// Content is the generated content.
	Content string `json:"content"`

	// TokensUsed is the number of tokens consumed.
	TokensUsed int `json:"tokens_used,omitempty"`

	// ProcessingTimeMs is how long generation took.
	ProcessingTimeMs int64 `json:"processing_time_ms"`

	// Error contains any error message.
	Error string `json:"error,omitempty"`
}

// GenerativeLLMPlugin extends LLMProviderPlugin with generic generation capabilities.
type GenerativeLLMPlugin interface {
	LLMProviderPlugin

	// Generate performs generic text generation.
	Generate(ctx context.Context, req *GenerateRequest) (*GenerateResponse, error)
}
