// Package llm provides types and utilities for LLM request/response handling.
package llm

import (
	"time"
)

// Provider represents an LLM provider.
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderAzure     Provider = "azure_openai"
	ProviderGoogle    Provider = "google"
	ProviderOllama    Provider = "ollama"
	ProviderUnknown   Provider = "unknown"
)

// RequestType represents the type of LLM request.
type RequestType string

const (
	RequestTypeChat       RequestType = "chat"
	RequestTypeCompletion RequestType = "completion"
	RequestTypeEmbedding  RequestType = "embedding"
	RequestTypeImage      RequestType = "image"
	RequestTypeAudio      RequestType = "audio"
	RequestTypeFile       RequestType = "file"
	RequestTypeUnknown    RequestType = "unknown"
)

// Role represents a message role in a conversation.
type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
	RoleFunction  Role = "function"
)

// Message represents a normalized chat message.
type Message struct {
	Role       Role              `json:"role"`
	Content    string            `json:"content"`
	Name       string            `json:"name,omitempty"`
	ToolCalls  []ToolCall        `json:"tool_calls,omitempty"`
	ToolCallID string            `json:"tool_call_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

// ToolCall represents a tool/function call in a message.
type ToolCall struct {
	ID       string            `json:"id"`
	Type     string            `json:"type"`
	Function FunctionCall      `json:"function"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// FunctionCall represents a function call within a tool call.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// Tool represents a tool definition.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

// ToolFunction represents a function definition in a tool.
type ToolFunction struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Parameters  interface{} `json:"parameters,omitempty"`
}

// Attachment represents a file or media attachment.
type Attachment struct {
	Type     string `json:"type"` // "file", "image", "audio"
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mime_type,omitempty"`
	Size     int64  `json:"size,omitempty"`
	URL      string `json:"url,omitempty"`
	Hash     string `json:"hash,omitempty"` // Content hash for audit
}

// Request represents a normalized LLM request.
type Request struct {
	// Identification
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	// Provider info
	Provider Provider `json:"provider"`
	Model    string   `json:"model"`
	Endpoint string   `json:"endpoint"`

	// Request classification
	RequestType RequestType `json:"request_type"`

	// Content
	Messages    []Message `json:"messages,omitempty"`
	Prompt      string    `json:"prompt,omitempty"` // For completion requests
	SystemPrompt string   `json:"system_prompt,omitempty"`

	// Tools
	Tools      []Tool `json:"tools,omitempty"`
	ToolChoice string `json:"tool_choice,omitempty"`

	// Attachments
	Attachments []Attachment `json:"attachments,omitempty"`

	// Parameters
	Temperature      *float64 `json:"temperature,omitempty"`
	MaxTokens        *int     `json:"max_tokens,omitempty"`
	TopP             *float64 `json:"top_p,omitempty"`
	FrequencyPenalty *float64 `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64 `json:"presence_penalty,omitempty"`
	Stop             []string `json:"stop,omitempty"`
	Stream           bool     `json:"stream,omitempty"`

	// Caller context
	User      string `json:"user,omitempty"`
	Tool      string `json:"tool,omitempty"` // Calling tool (claude_code, etc.)
	MachineID string `json:"machine_id,omitempty"`

	// Raw request for audit (hashed, not stored raw)
	RawRequestHash string `json:"raw_request_hash,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Response represents a normalized LLM response.
type Response struct {
	// Identification
	ID        string    `json:"id"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`

	// Provider info
	Provider Provider `json:"provider"`
	Model    string   `json:"model"`

	// Content
	Choices []Choice `json:"choices,omitempty"`

	// Usage
	Usage *Usage `json:"usage,omitempty"`

	// Streaming
	IsStreaming bool `json:"is_streaming,omitempty"`

	// Error (if any)
	Error *APIError `json:"error,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Choice represents a response choice.
type Choice struct {
	Index        int      `json:"index"`
	Message      *Message `json:"message,omitempty"`
	Delta        *Message `json:"delta,omitempty"` // For streaming
	FinishReason string   `json:"finish_reason,omitempty"`
}

// Usage represents token usage information.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// APIError represents an API error response.
type APIError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

// EvaluationRequest represents a request to evaluate an LLM call.
type EvaluationRequest struct {
	Request  *Request `json:"request"`
	Response *Response `json:"response,omitempty"` // Optional, for response scanning
}

// EvaluationResult represents the result of LLM request evaluation.
type EvaluationResult struct {
	// Decision
	Decision    string   `json:"decision"` // ALLOW, DENY, REDACT, TRANSFORM, ASK
	RiskScore   int      `json:"risk_score"`
	RiskCategories []string `json:"risk_categories"`
	ReasonCodes []string `json:"reason_codes"`
	Reasons     []string `json:"reasons"`

	// Policy info
	PolicyID     string   `json:"policy_id"`
	MatchedRules []string `json:"matched_rules"`

	// Modifications (if REDACT or TRANSFORM)
	Redactions      []Redaction      `json:"redactions,omitempty"`
	Transformations []Transformation `json:"transformations,omitempty"`
	ModifiedRequest *Request         `json:"modified_request,omitempty"`

	// Context for approval prompts
	Context string `json:"context,omitempty"`
}

// Redaction represents a redaction applied to the request.
type Redaction struct {
	Field       string `json:"field"`       // e.g., "messages[0].content"
	Type        string `json:"type"`        // e.g., "secret", "pii"
	Original    string `json:"original"`    // Original value (masked for logs)
	Replacement string `json:"replacement"` // Replacement value
	Reason      string `json:"reason"`
}

// Transformation represents a transformation applied to the request.
type Transformation struct {
	Type        string `json:"type"`   // e.g., "trim", "remove_attachment", "strip_stacktrace"
	Field       string `json:"field"`  // Field affected
	Description string `json:"description"`
}

// ContentSummary provides a summary of request content for risk assessment.
type ContentSummary struct {
	MessageCount     int      `json:"message_count"`
	TotalChars       int      `json:"total_chars"`
	HasSystemPrompt  bool     `json:"has_system_prompt"`
	HasTools         bool     `json:"has_tools"`
	HasAttachments   bool     `json:"has_attachments"`
	AttachmentTypes  []string `json:"attachment_types,omitempty"`
	DetectedSecrets  int      `json:"detected_secrets"`
	DetectedPII      int      `json:"detected_pii"`
	ContentClasses   []string `json:"content_classes"`
}

// GetContentSummary generates a content summary for the request.
func (r *Request) GetContentSummary() ContentSummary {
	summary := ContentSummary{
		MessageCount:    len(r.Messages),
		HasSystemPrompt: r.SystemPrompt != "",
		HasTools:        len(r.Tools) > 0,
		HasAttachments:  len(r.Attachments) > 0,
	}

	// Count total characters
	for _, msg := range r.Messages {
		summary.TotalChars += len(msg.Content)
	}
	summary.TotalChars += len(r.Prompt)
	summary.TotalChars += len(r.SystemPrompt)

	// Collect attachment types
	attachmentTypes := make(map[string]bool)
	for _, att := range r.Attachments {
		attachmentTypes[att.Type] = true
	}
	for t := range attachmentTypes {
		summary.AttachmentTypes = append(summary.AttachmentTypes, t)
	}

	return summary
}

// GetAllContent returns all text content for scanning.
func (r *Request) GetAllContent() string {
	var content string

	if r.SystemPrompt != "" {
		content += r.SystemPrompt + "\n"
	}

	for _, msg := range r.Messages {
		content += msg.Content + "\n"
	}

	if r.Prompt != "" {
		content += r.Prompt + "\n"
	}

	return content
}
