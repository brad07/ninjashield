// Package plugin provides the plugin system for NinjaShield.
package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPProviderConfig holds configuration for an HTTP-based LLM provider plugin.
type HTTPProviderConfig struct {
	// URL is the base URL of the LLM provider service.
	URL string `yaml:"url" json:"url"`

	// Timeout is the request timeout.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Headers are additional HTTP headers to include in requests.
	Headers map[string]string `yaml:"headers" json:"headers"`

	// APIKey is an optional API key for authentication.
	APIKey string `yaml:"api_key" json:"api_key"`

	// HealthEndpoint is the path for health checks (default: /health).
	HealthEndpoint string `yaml:"health_endpoint" json:"health_endpoint"`

	// AssessCommandEndpoint is the path for command assessment (default: /assess/command).
	AssessCommandEndpoint string `yaml:"assess_command_endpoint" json:"assess_command_endpoint"`

	// AssessContentEndpoint is the path for content assessment (default: /assess/content).
	AssessContentEndpoint string `yaml:"assess_content_endpoint" json:"assess_content_endpoint"`

	// RetryCount is the number of retries on failure.
	RetryCount int `yaml:"retry_count" json:"retry_count"`

	// RetryDelay is the delay between retries.
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`
}

// DefaultHTTPProviderConfig returns an HTTPProviderConfig with sensible defaults.
func DefaultHTTPProviderConfig() HTTPProviderConfig {
	return HTTPProviderConfig{
		Timeout:               30 * time.Second,
		HealthEndpoint:        "/health",
		AssessCommandEndpoint: "/assess/command",
		AssessContentEndpoint: "/assess/content",
		RetryCount:            2,
		RetryDelay:            500 * time.Millisecond,
	}
}

// HTTPProvider is an LLM provider plugin that communicates via HTTP.
type HTTPProvider struct {
	info   PluginInfo
	config HTTPProviderConfig
	client *http.Client
	status PluginStatus
}

// HTTPAssessCommandRequest is the request format for command assessment.
type HTTPAssessCommandRequest struct {
	Command     string            `json:"command"`
	Arguments   []string          `json:"arguments,omitempty"`
	WorkingDir  string            `json:"working_dir,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Context     AssessmentContext `json:"context,omitempty"`
}

// HTTPAssessContentRequest is the request format for content assessment.
type HTTPAssessContentRequest struct {
	Content     string            `json:"content"`
	ContentType string            `json:"content_type"`
	Context     AssessmentContext `json:"context,omitempty"`
}

// AssessmentContext provides context for risk assessment.
type AssessmentContext struct {
	Source      string   `json:"source,omitempty"`
	User        string   `json:"user,omitempty"`
	SessionID   string   `json:"session_id,omitempty"`
	PriorRisks  []string `json:"prior_risks,omitempty"`
	ProjectType string   `json:"project_type,omitempty"`
}

// HTTPAssessmentResponse is the response format from the LLM provider.
type HTTPAssessmentResponse struct {
	RiskScore      int            `json:"risk_score"`
	Confidence     float64        `json:"confidence"`
	Recommendation Recommendation `json:"recommendation"`
	Reasoning      string         `json:"reasoning"`
	RiskFactors    []string       `json:"risk_factors,omitempty"`
	Suggestions    []string       `json:"suggestions,omitempty"`
	Error          string         `json:"error,omitempty"`
}

// NewHTTPProvider creates a new HTTP-based LLM provider plugin.
func NewHTTPProvider(id, name string, config HTTPProviderConfig) *HTTPProvider {
	if config.Timeout == 0 {
		config.Timeout = DefaultHTTPProviderConfig().Timeout
	}
	if config.HealthEndpoint == "" {
		config.HealthEndpoint = DefaultHTTPProviderConfig().HealthEndpoint
	}
	if config.AssessCommandEndpoint == "" {
		config.AssessCommandEndpoint = DefaultHTTPProviderConfig().AssessCommandEndpoint
	}
	if config.AssessContentEndpoint == "" {
		config.AssessContentEndpoint = DefaultHTTPProviderConfig().AssessContentEndpoint
	}

	return &HTTPProvider{
		info: PluginInfo{
			ID:      fmt.Sprintf("llm:%s", id),
			Name:    name,
			Version: "1.0.0",
			Type:    PluginTypeLLMProvider,
			Tier:    TierHTTP,
		},
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
		status: PluginStatusUninitialized,
	}
}

// Info returns the plugin information.
func (p *HTTPProvider) Info() PluginInfo {
	return p.info
}

// Init initializes the HTTP provider.
func (p *HTTPProvider) Init(ctx context.Context, config map[string]any) error {
	// Parse additional config if provided
	if url, ok := config["url"].(string); ok {
		p.config.URL = url
	}
	if timeout, ok := config["timeout"].(time.Duration); ok {
		p.config.Timeout = timeout
		p.client.Timeout = timeout
	}
	if headers, ok := config["headers"].(map[string]string); ok {
		p.config.Headers = headers
	}
	if apiKey, ok := config["api_key"].(string); ok {
		p.config.APIKey = apiKey
	}

	// Verify connectivity
	if err := p.HealthCheck(ctx); err != nil {
		return fmt.Errorf("health check failed during init: %w", err)
	}

	p.status = PluginStatusReady
	return nil
}

// Shutdown shuts down the HTTP provider.
func (p *HTTPProvider) Shutdown(ctx context.Context) error {
	p.status = PluginStatusStopped
	return nil
}

// HealthCheck checks if the HTTP provider service is healthy.
func (p *HTTPProvider) HealthCheck(ctx context.Context) error {
	url := p.config.URL + p.config.HealthEndpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	p.addHeaders(req)

	resp, err := p.client.Do(req)
	if err != nil {
		p.status = PluginStatusError
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		p.status = PluginStatusError
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	p.status = PluginStatusReady
	return nil
}

// IsAvailable checks if the provider is available.
func (p *HTTPProvider) IsAvailable(ctx context.Context) bool {
	err := p.HealthCheck(ctx)
	return err == nil
}

// AssessCommand assesses the risk of a command.
func (p *HTTPProvider) AssessCommand(ctx context.Context, req *CommandAssessmentRequest) (*RiskAssessment, error) {
	httpReq := HTTPAssessCommandRequest{
		Command:    req.Command,
		WorkingDir: req.Context.WorkingDirectory,
		Context: AssessmentContext{
			Source: req.Context.Source,
			User:   req.Context.User,
		},
	}

	body, err := json.Marshal(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	response, err := p.doAssessmentRequest(ctx, p.config.AssessCommandEndpoint, body)
	if err != nil {
		return nil, err
	}

	return &RiskAssessment{
		Score:          response.RiskScore,
		Confidence:     response.Confidence,
		Recommendation: response.Recommendation,
		Explanation:    response.Reasoning,
		Categories:     response.RiskFactors,
	}, nil
}

// AssessContent assesses the risk of content.
func (p *HTTPProvider) AssessContent(ctx context.Context, req *ContentAssessmentRequest) (*RiskAssessment, error) {
	httpReq := HTTPAssessContentRequest{
		Content:     req.Content,
		ContentType: req.ContentType,
		Context: AssessmentContext{
			Source: req.Context.Source,
		},
	}

	body, err := json.Marshal(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	response, err := p.doAssessmentRequest(ctx, p.config.AssessContentEndpoint, body)
	if err != nil {
		return nil, err
	}

	return &RiskAssessment{
		Score:          response.RiskScore,
		Confidence:     response.Confidence,
		Recommendation: response.Recommendation,
		Explanation:    response.Reasoning,
		Categories:     response.RiskFactors,
	}, nil
}

// doAssessmentRequest performs an assessment HTTP request with retries.
func (p *HTTPProvider) doAssessmentRequest(ctx context.Context, endpoint string, body []byte) (*HTTPAssessmentResponse, error) {
	var lastErr error

	for attempt := 0; attempt <= p.config.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(p.config.RetryDelay)
		}

		response, err := p.doSingleRequest(ctx, endpoint, body)
		if err != nil {
			lastErr = err
			continue
		}

		return response, nil
	}

	return nil, fmt.Errorf("assessment failed after %d retries: %w", p.config.RetryCount+1, lastErr)
}

// doSingleRequest performs a single HTTP request.
func (p *HTTPProvider) doSingleRequest(ctx context.Context, endpoint string, body []byte) (*HTTPAssessmentResponse, error) {
	url := p.config.URL + endpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	p.addHeaders(req)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("assessment request returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response HTTPAssessmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Error != "" {
		return nil, fmt.Errorf("provider error: %s", response.Error)
	}

	return &response, nil
}

// addHeaders adds configured headers to a request.
func (p *HTTPProvider) addHeaders(req *http.Request) {
	if p.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	}
	for key, value := range p.config.Headers {
		req.Header.Set(key, value)
	}
}

// SupportsStreaming returns whether this provider supports streaming responses.
func (p *HTTPProvider) SupportsStreaming() bool {
	return false // HTTP providers don't support streaming by default
}

// ModelInfo returns information about the model.
func (p *HTTPProvider) ModelInfo() ModelInfo {
	return ModelInfo{
		Name:     "HTTP Provider",
		Provider: "http",
	}
}

// HTTPProviderFactory creates HTTP provider instances from configuration.
type HTTPProviderFactory struct{}

// Create creates a new HTTP provider from configuration.
func (f *HTTPProviderFactory) Create(name string, config map[string]any) (LLMProviderPlugin, error) {
	providerConfig := DefaultHTTPProviderConfig()

	if url, ok := config["url"].(string); ok {
		providerConfig.URL = url
	} else {
		return nil, fmt.Errorf("url is required for HTTP provider")
	}

	if timeout, ok := config["timeout"].(string); ok {
		d, err := time.ParseDuration(timeout)
		if err == nil {
			providerConfig.Timeout = d
		}
	}

	if headers, ok := config["headers"].(map[string]any); ok {
		providerConfig.Headers = make(map[string]string)
		for k, v := range headers {
			if s, ok := v.(string); ok {
				providerConfig.Headers[k] = s
			}
		}
	}

	if apiKey, ok := config["api_key"].(string); ok {
		providerConfig.APIKey = apiKey
	}

	if healthEndpoint, ok := config["health_endpoint"].(string); ok {
		providerConfig.HealthEndpoint = healthEndpoint
	}

	if assessCommandEndpoint, ok := config["assess_command_endpoint"].(string); ok {
		providerConfig.AssessCommandEndpoint = assessCommandEndpoint
	}

	if assessContentEndpoint, ok := config["assess_content_endpoint"].(string); ok {
		providerConfig.AssessContentEndpoint = assessContentEndpoint
	}

	displayName := name
	if n, ok := config["name"].(string); ok {
		displayName = n
	}

	return NewHTTPProvider(name, displayName, providerConfig), nil
}

// RegisterHTTPProviderFactory registers the HTTP provider factory with the global registry.
func RegisterHTTPProviderFactory() {
	factory := &HTTPProviderFactory{}
	RegisterLLMProvider("http", func() LLMProviderPlugin {
		// Return a placeholder - actual instances are created via factory.Create
		return NewHTTPProvider("http", "HTTP Provider", DefaultHTTPProviderConfig())
	})
	_ = factory // Factory is available for programmatic use
}
