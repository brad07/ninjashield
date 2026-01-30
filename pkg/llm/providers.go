package llm

import (
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProviderInfo contains information about a detected provider.
type ProviderInfo struct {
	Provider    Provider
	BaseURL     string
	APIVersion  string
	IsSupported bool
}

// ProviderPatterns maps URL patterns to providers.
var ProviderPatterns = map[string]Provider{
	"api.openai.com":          ProviderOpenAI,
	"api.anthropic.com":       ProviderAnthropic,
	"openai.azure.com":        ProviderAzure,
	"generativelanguage.googleapis.com": ProviderGoogle,
	"aiplatform.googleapis.com": ProviderGoogle,
	"localhost:11434":         ProviderOllama,
	"127.0.0.1:11434":         ProviderOllama,
}

// DetectProvider detects the LLM provider from a URL.
func DetectProvider(urlStr string) ProviderInfo {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ProviderInfo{Provider: ProviderUnknown}
	}

	host := parsed.Host

	// Check exact matches first
	if provider, ok := ProviderPatterns[host]; ok {
		return ProviderInfo{
			Provider:    provider,
			BaseURL:     parsed.Scheme + "://" + host,
			IsSupported: true,
		}
	}

	// Check partial matches
	for pattern, provider := range ProviderPatterns {
		if strings.Contains(host, pattern) {
			return ProviderInfo{
				Provider:    provider,
				BaseURL:     parsed.Scheme + "://" + host,
				IsSupported: true,
			}
		}
	}

	return ProviderInfo{
		Provider:    ProviderUnknown,
		BaseURL:     parsed.Scheme + "://" + host,
		IsSupported: false,
	}
}

// DetectRequestType determines the request type from the endpoint path.
func DetectRequestType(path string) RequestType {
	path = strings.ToLower(path)

	switch {
	case strings.Contains(path, "/chat/completions"):
		return RequestTypeChat
	case strings.Contains(path, "/completions"):
		return RequestTypeCompletion
	case strings.Contains(path, "/embeddings"):
		return RequestTypeEmbedding
	case strings.Contains(path, "/images"):
		return RequestTypeImage
	case strings.Contains(path, "/audio"):
		return RequestTypeAudio
	case strings.Contains(path, "/files"):
		return RequestTypeFile
	case strings.Contains(path, "/messages"): // Anthropic
		return RequestTypeChat
	default:
		return RequestTypeUnknown
	}
}

// Parser handles parsing of provider-specific request formats.
type Parser struct{}

// NewParser creates a new request parser.
func NewParser() *Parser {
	return &Parser{}
}

// ParseRequest parses a raw request body into a normalized Request.
func (p *Parser) ParseRequest(provider Provider, endpoint string, body []byte) (*Request, error) {
	switch provider {
	case ProviderOpenAI, ProviderAzure:
		return p.parseOpenAIRequest(endpoint, body)
	case ProviderAnthropic:
		return p.parseAnthropicRequest(endpoint, body)
	case ProviderGoogle:
		return p.parseGoogleRequest(endpoint, body)
	case ProviderOllama:
		return p.parseOllamaRequest(endpoint, body)
	default:
		return p.parseGenericRequest(endpoint, body)
	}
}

// OpenAI format types
type openAIRequest struct {
	Model            string             `json:"model"`
	Messages         []openAIMessage    `json:"messages,omitempty"`
	Prompt           interface{}        `json:"prompt,omitempty"` // string or []string
	Temperature      *float64           `json:"temperature,omitempty"`
	MaxTokens        *int               `json:"max_tokens,omitempty"`
	TopP             *float64           `json:"top_p,omitempty"`
	FrequencyPenalty *float64           `json:"frequency_penalty,omitempty"`
	PresencePenalty  *float64           `json:"presence_penalty,omitempty"`
	Stop             interface{}        `json:"stop,omitempty"` // string or []string
	Stream           bool               `json:"stream,omitempty"`
	Tools            []openAITool       `json:"tools,omitempty"`
	ToolChoice       interface{}        `json:"tool_choice,omitempty"`
	User             string             `json:"user,omitempty"`
}

type openAIMessage struct {
	Role       string           `json:"role"`
	Content    interface{}      `json:"content"` // string or []content_part
	Name       string           `json:"name,omitempty"`
	ToolCalls  []openAIToolCall `json:"tool_calls,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
}

type openAIToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type openAITool struct {
	Type     string `json:"type"`
	Function struct {
		Name        string      `json:"name"`
		Description string      `json:"description,omitempty"`
		Parameters  interface{} `json:"parameters,omitempty"`
	} `json:"function"`
}

func (p *Parser) parseOpenAIRequest(endpoint string, body []byte) (*Request, error) {
	var raw openAIRequest
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	req := &Request{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		Provider:    ProviderOpenAI,
		Model:       raw.Model,
		Endpoint:    endpoint,
		RequestType: DetectRequestType(endpoint),
		Temperature: raw.Temperature,
		MaxTokens:   raw.MaxTokens,
		TopP:        raw.TopP,
		FrequencyPenalty: raw.FrequencyPenalty,
		PresencePenalty:  raw.PresencePenalty,
		Stream:      raw.Stream,
		User:        raw.User,
	}

	// Parse messages
	for _, msg := range raw.Messages {
		content := extractContent(msg.Content)

		m := Message{
			Role:       Role(msg.Role),
			Content:    content,
			Name:       msg.Name,
			ToolCallID: msg.ToolCallID,
		}

		// Parse tool calls
		for _, tc := range msg.ToolCalls {
			m.ToolCalls = append(m.ToolCalls, ToolCall{
				ID:   tc.ID,
				Type: tc.Type,
				Function: FunctionCall{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}

		req.Messages = append(req.Messages, m)
	}

	// Parse prompt (for completion requests)
	if raw.Prompt != nil {
		req.Prompt = extractContent(raw.Prompt)
	}

	// Parse tools
	for _, tool := range raw.Tools {
		req.Tools = append(req.Tools, Tool{
			Type: tool.Type,
			Function: ToolFunction{
				Name:        tool.Function.Name,
				Description: tool.Function.Description,
				Parameters:  tool.Function.Parameters,
			},
		})
	}

	// Parse stop sequences
	if raw.Stop != nil {
		req.Stop = extractStringSlice(raw.Stop)
	}

	return req, nil
}

// Anthropic format types
type anthropicRequest struct {
	Model       string             `json:"model"`
	Messages    []anthropicMessage `json:"messages"`
	System      string             `json:"system,omitempty"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature *float64           `json:"temperature,omitempty"`
	TopP        *float64           `json:"top_p,omitempty"`
	Stream      bool               `json:"stream,omitempty"`
	Tools       []anthropicTool    `json:"tools,omitempty"`
}

type anthropicMessage struct {
	Role    string      `json:"role"`
	Content interface{} `json:"content"` // string or []content_block
}

type anthropicTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	InputSchema interface{} `json:"input_schema"`
}

func (p *Parser) parseAnthropicRequest(endpoint string, body []byte) (*Request, error) {
	var raw anthropicRequest
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	maxTokens := raw.MaxTokens
	req := &Request{
		ID:           uuid.New().String(),
		Timestamp:    time.Now(),
		Provider:     ProviderAnthropic,
		Model:        raw.Model,
		Endpoint:     endpoint,
		RequestType:  RequestTypeChat,
		SystemPrompt: raw.System,
		Temperature:  raw.Temperature,
		MaxTokens:    &maxTokens,
		TopP:         raw.TopP,
		Stream:       raw.Stream,
	}

	// Parse messages
	for _, msg := range raw.Messages {
		content := extractContent(msg.Content)
		req.Messages = append(req.Messages, Message{
			Role:    Role(msg.Role),
			Content: content,
		})
	}

	// Parse tools
	for _, tool := range raw.Tools {
		req.Tools = append(req.Tools, Tool{
			Type: "function",
			Function: ToolFunction{
				Name:        tool.Name,
				Description: tool.Description,
				Parameters:  tool.InputSchema,
			},
		})
	}

	return req, nil
}

func (p *Parser) parseGoogleRequest(endpoint string, body []byte) (*Request, error) {
	// Google has a different format - simplified parsing
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	req := &Request{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		Provider:    ProviderGoogle,
		Endpoint:    endpoint,
		RequestType: DetectRequestType(endpoint),
	}

	// Extract model from endpoint or body
	if model, ok := raw["model"].(string); ok {
		req.Model = model
	}

	// Extract contents
	if contents, ok := raw["contents"].([]interface{}); ok {
		for _, c := range contents {
			if content, ok := c.(map[string]interface{}); ok {
				role := "user"
				if r, ok := content["role"].(string); ok {
					role = r
				}

				text := ""
				if parts, ok := content["parts"].([]interface{}); ok {
					for _, part := range parts {
						if p, ok := part.(map[string]interface{}); ok {
							if t, ok := p["text"].(string); ok {
								text += t
							}
						}
					}
				}

				req.Messages = append(req.Messages, Message{
					Role:    Role(role),
					Content: text,
				})
			}
		}
	}

	return req, nil
}

func (p *Parser) parseOllamaRequest(endpoint string, body []byte) (*Request, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	req := &Request{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		Provider:    ProviderOllama,
		Endpoint:    endpoint,
		RequestType: DetectRequestType(endpoint),
	}

	if model, ok := raw["model"].(string); ok {
		req.Model = model
	}

	// Ollama chat format
	if messages, ok := raw["messages"].([]interface{}); ok {
		for _, m := range messages {
			if msg, ok := m.(map[string]interface{}); ok {
				role := "user"
				if r, ok := msg["role"].(string); ok {
					role = r
				}
				content := ""
				if c, ok := msg["content"].(string); ok {
					content = c
				}
				req.Messages = append(req.Messages, Message{
					Role:    Role(role),
					Content: content,
				})
			}
		}
	}

	// Ollama generate format
	if prompt, ok := raw["prompt"].(string); ok {
		req.Prompt = prompt
	}

	if system, ok := raw["system"].(string); ok {
		req.SystemPrompt = system
	}

	if stream, ok := raw["stream"].(bool); ok {
		req.Stream = stream
	}

	return req, nil
}

func (p *Parser) parseGenericRequest(endpoint string, body []byte) (*Request, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, err
	}

	req := &Request{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		Provider:    ProviderUnknown,
		Endpoint:    endpoint,
		RequestType: DetectRequestType(endpoint),
		Metadata:    raw,
	}

	if model, ok := raw["model"].(string); ok {
		req.Model = model
	}

	return req, nil
}

// Helper functions

func extractContent(v interface{}) string {
	switch c := v.(type) {
	case string:
		return c
	case []interface{}:
		// Handle content parts array
		var texts []string
		for _, part := range c {
			if p, ok := part.(map[string]interface{}); ok {
				if text, ok := p["text"].(string); ok {
					texts = append(texts, text)
				}
			}
		}
		return strings.Join(texts, "\n")
	default:
		return ""
	}
}

func extractStringSlice(v interface{}) []string {
	switch s := v.(type) {
	case string:
		return []string{s}
	case []interface{}:
		var result []string
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case []string:
		return s
	default:
		return nil
	}
}
