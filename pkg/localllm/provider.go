// Package localllm provides a generic interface for local LLM providers.
package localllm

import (
	"context"
	"fmt"
)

// Provider represents a local LLM provider (Ollama, LMStudio, etc.)
type Provider interface {
	// Name returns the provider name
	Name() string

	// IsAvailable checks if the provider is running and accessible
	IsAvailable(ctx context.Context) bool

	// AssessCommand evaluates a shell command for security risks
	AssessCommand(ctx context.Context, summary CommandSummary) (*RiskAssessment, error)

	// AssessContent evaluates content (for LLM request filtering)
	AssessContent(ctx context.Context, summary ContentSummary) (*RiskAssessment, error)

	// Generate sends a raw prompt and returns the response
	Generate(ctx context.Context, prompt string) (string, error)
}

// ProviderType identifies the type of LLM provider
type ProviderType string

const (
	ProviderOllama   ProviderType = "ollama"
	ProviderLMStudio ProviderType = "lmstudio"
	ProviderLocalAI  ProviderType = "localai"
	ProviderCustom   ProviderType = "custom"
)

// Config holds common configuration for local LLM providers.
type Config struct {
	Type     ProviderType
	Endpoint string // API endpoint URL
	Model    string // Model name to use
	Mode     Mode   // Scoring mode (fast/strict)
	APIKey   string // Optional API key (for some providers)
}

// Mode represents the scoring mode.
type Mode string

const (
	ModeOff    Mode = "off"
	ModeFast   Mode = "fast"
	ModeStrict Mode = "strict"
)

// CommandSummary provides context for command risk assessment.
type CommandSummary struct {
	Command       string   `json:"command"`
	Cwd           string   `json:"cwd"`
	User          string   `json:"user"`
	Tool          string   `json:"tool"`
	DetectedRisks []string `json:"detected_risks"`
	InitialScore  int      `json:"initial_score"`
}

// ContentSummary provides context for content risk assessment.
type ContentSummary struct {
	Provider        string   `json:"provider"`
	Model           string   `json:"model"`
	RequestType     string   `json:"request_type"`
	MessageCount    int      `json:"message_count"`
	HasAttachments  bool     `json:"has_attachments"`
	HasTools        bool     `json:"has_tools"`
	DetectedSecrets int      `json:"detected_secrets"`
	DetectedPII     int      `json:"detected_pii"`
	ContentClasses  []string `json:"content_classes"`
	ContentPreview  string   `json:"content_preview"`
}

// RiskAssessment represents the result of AI risk scoring.
type RiskAssessment struct {
	RiskScore         int      `json:"risk_score"`          // 0-100
	RiskCategories    []string `json:"risk_categories"`     // e.g., ["exfiltration", "reverse_shell"]
	RecommendedAction string   `json:"recommended_action"`  // "allow", "deny", "ask", "redact"
	Explanation       string   `json:"explanation"`         // Human-readable explanation
	Confidence        float64  `json:"confidence"`          // 0.0-1.0
}

// DefaultEndpoints returns the default endpoint for each provider type.
func DefaultEndpoints() map[ProviderType]string {
	return map[ProviderType]string{
		ProviderOllama:   "http://localhost:11434",
		ProviderLMStudio: "http://localhost:1234",
		ProviderLocalAI:  "http://localhost:8080",
	}
}

// DefaultConfig returns a default configuration for the given provider type.
func DefaultConfig(providerType ProviderType) Config {
	endpoints := DefaultEndpoints()
	endpoint, ok := endpoints[providerType]
	if !ok {
		endpoint = "http://localhost:8080"
	}

	model := "default"
	switch providerType {
	case ProviderOllama:
		model = "gemma3"
	case ProviderLMStudio:
		model = "local-model"
	case ProviderLocalAI:
		model = "gpt-3.5-turbo"
	}

	return Config{
		Type:     providerType,
		Endpoint: endpoint,
		Model:    model,
		Mode:     ModeFast,
	}
}

// Registry holds available provider factories
var providerFactories = make(map[ProviderType]ProviderFactory)

// ProviderFactory creates a provider from config
type ProviderFactory func(config Config) (Provider, error)

// RegisterProvider registers a provider factory
func RegisterProvider(providerType ProviderType, factory ProviderFactory) {
	providerFactories[providerType] = factory
}

// NewProvider creates a new provider based on the config
func NewProvider(config Config) (Provider, error) {
	factory, ok := providerFactories[config.Type]
	if !ok {
		return nil, fmt.Errorf("unknown provider type: %s", config.Type)
	}
	return factory(config)
}

// AvailableProviders returns a list of registered provider types
func AvailableProviders() []ProviderType {
	types := make([]ProviderType, 0, len(providerFactories))
	for t := range providerFactories {
		types = append(types, t)
	}
	return types
}
