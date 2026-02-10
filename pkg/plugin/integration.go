// Package plugin provides the plugin system for NinjaShield.
package plugin

import (
	"context"
	"time"
)

// IntegrationType represents the category of integration.
type IntegrationType string

const (
	// IntegrationTypeCLIHook is for CLI-based integrations (shell hooks).
	IntegrationTypeCLIHook IntegrationType = "cli_hook"
	// IntegrationTypeWebhook is for HTTP webhook-based integrations.
	IntegrationTypeWebhook IntegrationType = "webhook"
	// IntegrationTypeIDE is for IDE integrations (VSCode, JetBrains, etc.).
	IntegrationTypeIDE IntegrationType = "ide"
	// IntegrationTypeAPI is for direct API integrations.
	IntegrationTypeAPI IntegrationType = "api"
)

// IntegrationRequest represents an incoming request from an integration.
type IntegrationRequest struct {
	// ID is a unique identifier for this request.
	ID string `json:"id"`

	// IntegrationID identifies which integration sent this request.
	IntegrationID string `json:"integration_id"`

	// RequestType categorizes the request (e.g., "tool_call", "command", "file_write").
	RequestType string `json:"request_type"`

	// Payload contains the integration-specific request data.
	Payload IntegrationPayload `json:"payload"`

	// Context provides additional context about the request.
	Context IntegrationContext `json:"context,omitempty"`

	// Timestamp is when the request was received.
	Timestamp time.Time `json:"timestamp"`
}

// IntegrationPayload contains the actual content to evaluate.
type IntegrationPayload struct {
	// ToolName is the name of the tool being called (for tool-based integrations).
	ToolName string `json:"tool_name,omitempty"`

	// ToolInput contains the tool's input parameters.
	ToolInput map[string]any `json:"tool_input,omitempty"`

	// Command is the command being executed (for command-based requests).
	Command string `json:"command,omitempty"`

	// Content is raw content to evaluate (for content-based requests).
	Content string `json:"content,omitempty"`

	// ContentType describes the type of content.
	ContentType string `json:"content_type,omitempty"`

	// FilePath is the path of the file being operated on.
	FilePath string `json:"file_path,omitempty"`

	// FileContent is the content being written to a file.
	FileContent string `json:"file_content,omitempty"`

	// Raw contains the original unparsed request for custom handling.
	Raw []byte `json:"raw,omitempty"`
}

// IntegrationContext provides context about the integration request.
type IntegrationContext struct {
	// User is the user or process making the request.
	User string `json:"user,omitempty"`

	// SessionID links related requests together.
	SessionID string `json:"session_id,omitempty"`

	// WorkingDirectory is the current working directory.
	WorkingDirectory string `json:"working_directory,omitempty"`

	// ProjectPath is the root path of the project.
	ProjectPath string `json:"project_path,omitempty"`

	// Environment contains relevant environment variables.
	Environment map[string]string `json:"environment,omitempty"`

	// Metadata contains additional integration-specific context.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// IntegrationResponse is the response sent back to an integration.
type IntegrationResponse struct {
	// RequestID matches the request ID for correlation.
	RequestID string `json:"request_id"`

	// Allowed indicates whether the operation should proceed.
	Allowed bool `json:"allowed"`

	// Decision is the detailed decision (allow, deny, ask, transform).
	Decision string `json:"decision"`

	// RiskScore is the calculated risk score (0-100).
	RiskScore int `json:"risk_score"`

	// Reason explains the decision.
	Reason string `json:"reason,omitempty"`

	// Findings contains detailed security findings.
	Findings []IntegrationFinding `json:"findings,omitempty"`

	// ModifiedPayload contains a transformed version of the request, if applicable.
	ModifiedPayload *IntegrationPayload `json:"modified_payload,omitempty"`

	// Suggestions are recommendations for safer alternatives.
	Suggestions []string `json:"suggestions,omitempty"`

	// ProcessingTimeMs is how long evaluation took.
	ProcessingTimeMs int64 `json:"processing_time_ms"`

	// Error contains any error message.
	Error string `json:"error,omitempty"`
}

// IntegrationFinding represents a security finding for the integration.
type IntegrationFinding struct {
	Type       string  `json:"type"`
	Category   string  `json:"category"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
	Confidence float64 `json:"confidence"`
	Location   string  `json:"location,omitempty"`
}

// IntegrationPlugin is the interface for integration plugins.
type IntegrationPlugin interface {
	Plugin

	// Type returns the integration type.
	Type() IntegrationType

	// ParseRequest parses raw input into an IntegrationRequest.
	// This allows each integration to handle its specific input format.
	ParseRequest(ctx context.Context, raw []byte) (*IntegrationRequest, error)

	// FormatResponse formats a PipelineResponse into the integration's expected output.
	FormatResponse(ctx context.Context, req *IntegrationRequest, resp *PipelineResponse) (*IntegrationResponse, error)

	// HandleRequest processes a request through the full pipeline.
	// This is a convenience method that combines ParseRequest, pipeline evaluation, and FormatResponse.
	HandleRequest(ctx context.Context, raw []byte) (*IntegrationResponse, error)

	// ValidateConfig validates integration-specific configuration.
	ValidateConfig(config map[string]any) error

	// SupportedRequestTypes returns the request types this integration handles.
	SupportedRequestTypes() []string
}

// IntegrationConfig holds configuration for an integration plugin.
type IntegrationConfig struct {
	// ID is the integration identifier.
	ID string `yaml:"id" json:"id"`

	// Name is the human-readable name.
	Name string `yaml:"name" json:"name"`

	// Enabled determines if the integration is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Type is the integration type.
	Type IntegrationType `yaml:"type" json:"type"`

	// RiskTolerance overrides the default risk tolerance for this integration.
	RiskTolerance string `yaml:"risk_tolerance,omitempty" json:"risk_tolerance,omitempty"`

	// WebhookPath is the HTTP path for webhook integrations.
	WebhookPath string `yaml:"webhook_path,omitempty" json:"webhook_path,omitempty"`

	// WebhookSecret is used to verify webhook requests.
	WebhookSecret string `yaml:"webhook_secret,omitempty" json:"webhook_secret,omitempty"`

	// AllowedTools lists tools that are pre-approved (bypass evaluation).
	AllowedTools []string `yaml:"allowed_tools,omitempty" json:"allowed_tools,omitempty"`

	// BlockedTools lists tools that are always blocked.
	BlockedTools []string `yaml:"blocked_tools,omitempty" json:"blocked_tools,omitempty"`

	// Config contains integration-specific configuration.
	Config map[string]any `yaml:"config,omitempty" json:"config,omitempty"`
}

// IntegrationFactory is a function that creates a new IntegrationPlugin instance.
type IntegrationFactory func() IntegrationPlugin

// BaseIntegration provides common functionality for integration plugins.
type BaseIntegration struct {
	info     PluginInfo
	config   IntegrationConfig
	pipeline *Pipeline
	status   PluginStatus
}

// NewBaseIntegration creates a new BaseIntegration.
func NewBaseIntegration(id, name string, integrationType IntegrationType) *BaseIntegration {
	return &BaseIntegration{
		info: PluginInfo{
			ID:      "integration:" + id,
			Name:    name,
			Version: "1.0.0",
			Type:    PluginTypeIntegration,
			Tier:    TierCompileTime,
		},
		config: IntegrationConfig{
			ID:      id,
			Name:    name,
			Enabled: true,
			Type:    integrationType,
		},
		status: PluginStatusUninitialized,
	}
}

// Info returns the plugin information.
func (b *BaseIntegration) Info() PluginInfo {
	return b.info
}

// Init initializes the base integration.
func (b *BaseIntegration) Init(ctx context.Context, config map[string]any) error {
	// Parse config
	if id, ok := config["id"].(string); ok {
		b.config.ID = id
	}
	if name, ok := config["name"].(string); ok {
		b.config.Name = name
	}
	if enabled, ok := config["enabled"].(bool); ok {
		b.config.Enabled = enabled
	}
	if tolerance, ok := config["risk_tolerance"].(string); ok {
		b.config.RiskTolerance = tolerance
	}
	if webhookPath, ok := config["webhook_path"].(string); ok {
		b.config.WebhookPath = webhookPath
	}
	if webhookSecret, ok := config["webhook_secret"].(string); ok {
		b.config.WebhookSecret = webhookSecret
	}
	if allowedTools, ok := config["allowed_tools"].([]string); ok {
		b.config.AllowedTools = allowedTools
	}
	if blockedTools, ok := config["blocked_tools"].([]string); ok {
		b.config.BlockedTools = blockedTools
	}

	b.status = PluginStatusReady
	return nil
}

// Shutdown shuts down the integration.
func (b *BaseIntegration) Shutdown(ctx context.Context) error {
	b.status = PluginStatusStopped
	return nil
}

// HealthCheck checks if the integration is healthy.
func (b *BaseIntegration) HealthCheck(ctx context.Context) error {
	if b.status != PluginStatusReady {
		return ErrPluginNotInitialized
	}
	return nil
}

// SetPipeline sets the evaluation pipeline for the integration.
func (b *BaseIntegration) SetPipeline(pipeline *Pipeline) {
	b.pipeline = pipeline
}

// GetPipeline returns the evaluation pipeline.
func (b *BaseIntegration) GetPipeline() *Pipeline {
	return b.pipeline
}

// Config returns the integration configuration.
func (b *BaseIntegration) Config() IntegrationConfig {
	return b.config
}

// IsToolAllowed checks if a tool is in the allowed list.
func (b *BaseIntegration) IsToolAllowed(toolName string) bool {
	for _, t := range b.config.AllowedTools {
		if t == toolName || t == "*" {
			return true
		}
	}
	return false
}

// IsToolBlocked checks if a tool is in the blocked list.
func (b *BaseIntegration) IsToolBlocked(toolName string) bool {
	for _, t := range b.config.BlockedTools {
		if t == toolName || t == "*" {
			return true
		}
	}
	return false
}

// ConvertFindingsToIntegration converts scanner findings to integration findings.
func ConvertFindingsToIntegration(findings []Finding) []IntegrationFinding {
	result := make([]IntegrationFinding, len(findings))
	for i, f := range findings {
		result[i] = IntegrationFinding{
			Type:       f.Type,
			Category:   f.Category,
			Severity:   f.Severity,
			Message:    f.Message,
			Confidence: f.Confidence,
		}
	}
	return result
}

// Finding is imported from scanners but redefined here for convenience.
type Finding struct {
	Type       string  `json:"type"`
	Category   string  `json:"category"`
	Severity   string  `json:"severity"`
	Message    string  `json:"message"`
	Confidence float64 `json:"confidence"`
}
