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

	"github.com/brad07/ninjashield/pkg/scanners"
)

// HTTPScannerConfig holds configuration for an HTTP-based scanner plugin.
type HTTPScannerConfig struct {
	// URL is the base URL of the scanner service.
	URL string `yaml:"url" json:"url"`

	// Timeout is the request timeout.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// Headers are additional HTTP headers to include in requests.
	Headers map[string]string `yaml:"headers" json:"headers"`

	// HealthEndpoint is the path for health checks (default: /health).
	HealthEndpoint string `yaml:"health_endpoint" json:"health_endpoint"`

	// ScanEndpoint is the path for scan requests (default: /scan).
	ScanEndpoint string `yaml:"scan_endpoint" json:"scan_endpoint"`

	// Priority is the scanner priority (higher = runs first).
	Priority int `yaml:"priority" json:"priority"`

	// RetryCount is the number of retries on failure.
	RetryCount int `yaml:"retry_count" json:"retry_count"`

	// RetryDelay is the delay between retries.
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`
}

// DefaultHTTPScannerConfig returns an HTTPScannerConfig with sensible defaults.
func DefaultHTTPScannerConfig() HTTPScannerConfig {
	return HTTPScannerConfig{
		Timeout:        5 * time.Second,
		HealthEndpoint: "/health",
		ScanEndpoint:   "/scan",
		Priority:       50,
		RetryCount:     2,
		RetryDelay:     100 * time.Millisecond,
	}
}

// HTTPScanner is a scanner plugin that communicates via HTTP.
type HTTPScanner struct {
	info       PluginInfo
	config     HTTPScannerConfig
	client     *http.Client
	status     PluginStatus
	contentTypes []string
}

// HTTPScanRequest is the request format for HTTP scanners.
type HTTPScanRequest struct {
	ID          string                 `json:"id"`
	Content     string                 `json:"content"`
	ContentType string                 `json:"content_type"`
	Source      string                 `json:"source,omitempty"`
	User        string                 `json:"user,omitempty"`
	WorkingDir  string                 `json:"working_dir,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// HTTPScanResponse is the response format from HTTP scanners.
type HTTPScanResponse struct {
	RequestID        string             `json:"request_id"`
	Findings         []scanners.Finding `json:"findings"`
	RiskScore        int                `json:"risk_score"`
	ProcessingTimeMs int64              `json:"processing_time_ms"`
	Error            string             `json:"error,omitempty"`
}

// NewHTTPScanner creates a new HTTP-based scanner plugin.
func NewHTTPScanner(id, name string, config HTTPScannerConfig) *HTTPScanner {
	if config.Timeout == 0 {
		config.Timeout = DefaultHTTPScannerConfig().Timeout
	}
	if config.HealthEndpoint == "" {
		config.HealthEndpoint = DefaultHTTPScannerConfig().HealthEndpoint
	}
	if config.ScanEndpoint == "" {
		config.ScanEndpoint = DefaultHTTPScannerConfig().ScanEndpoint
	}

	return &HTTPScanner{
		info: PluginInfo{
			ID:      fmt.Sprintf("scanner:%s", id),
			Name:    name,
			Version: "1.0.0",
			Type:    PluginTypeScanner,
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
func (s *HTTPScanner) Info() PluginInfo {
	return s.info
}

// Init initializes the HTTP scanner.
func (s *HTTPScanner) Init(ctx context.Context, config map[string]any) error {
	// Parse additional config if provided
	if url, ok := config["url"].(string); ok {
		s.config.URL = url
	}
	if timeout, ok := config["timeout"].(time.Duration); ok {
		s.config.Timeout = timeout
		s.client.Timeout = timeout
	}
	if headers, ok := config["headers"].(map[string]string); ok {
		s.config.Headers = headers
	}
	if priority, ok := config["priority"].(int); ok {
		s.config.Priority = priority
	}
	if contentTypes, ok := config["content_types"].([]string); ok {
		s.contentTypes = contentTypes
	}

	// Verify connectivity
	if err := s.HealthCheck(ctx); err != nil {
		return fmt.Errorf("health check failed during init: %w", err)
	}

	s.status = PluginStatusReady
	return nil
}

// Shutdown shuts down the HTTP scanner.
func (s *HTTPScanner) Shutdown(ctx context.Context) error {
	s.status = PluginStatusStopped
	return nil
}

// HealthCheck checks if the HTTP scanner service is healthy.
func (s *HTTPScanner) HealthCheck(ctx context.Context) error {
	url := s.config.URL + s.config.HealthEndpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	s.addHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		s.status = PluginStatusError
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		s.status = PluginStatusError
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	s.status = PluginStatusReady
	return nil
}

// Scan sends a scan request to the HTTP scanner service.
func (s *HTTPScanner) Scan(ctx context.Context, req *ScanRequest) (*ScanResponse, error) {
	start := time.Now()

	// Build HTTP request
	httpReq := HTTPScanRequest{
		ID:          req.ID,
		Content:     req.Content,
		ContentType: req.ContentType,
		Source:      req.Context.Source,
		User:        req.Context.User,
		WorkingDir:  req.Context.WorkingDirectory,
		Metadata:    req.Context.Metadata,
	}

	body, err := json.Marshal(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Execute with retries
	var lastErr error
	for attempt := 0; attempt <= s.config.RetryCount; attempt++ {
		if attempt > 0 {
			time.Sleep(s.config.RetryDelay)
		}

		response, err := s.doScanRequest(ctx, body)
		if err != nil {
			lastErr = err
			continue
		}

		return &ScanResponse{
			RequestID:        response.RequestID,
			PluginID:         s.info.ID,
			Findings:         response.Findings,
			RiskScore:        response.RiskScore,
			ProcessingTimeMs: time.Since(start).Milliseconds(),
		}, nil
	}

	return nil, fmt.Errorf("scan failed after %d retries: %w", s.config.RetryCount+1, lastErr)
}

// doScanRequest performs a single scan HTTP request.
func (s *HTTPScanner) doScanRequest(ctx context.Context, body []byte) (*HTTPScanResponse, error) {
	url := s.config.URL + s.config.ScanEndpoint

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	s.addHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("scan request returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var response HTTPScanResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if response.Error != "" {
		return nil, fmt.Errorf("scanner error: %s", response.Error)
	}

	return &response, nil
}

// addHeaders adds configured headers to a request.
func (s *HTTPScanner) addHeaders(req *http.Request) {
	for key, value := range s.config.Headers {
		req.Header.Set(key, value)
	}
}

// Priority returns the scanner priority.
func (s *HTTPScanner) Priority() int {
	return s.config.Priority
}

// SupportedContentTypes returns the content types this scanner can handle.
func (s *HTTPScanner) SupportedContentTypes() []string {
	return s.contentTypes
}

// HTTPScannerFactory creates HTTP scanner instances from configuration.
type HTTPScannerFactory struct{}

// Create creates a new HTTP scanner from configuration.
func (f *HTTPScannerFactory) Create(name string, config map[string]any) (ScannerPlugin, error) {
	scannerConfig := DefaultHTTPScannerConfig()

	if url, ok := config["url"].(string); ok {
		scannerConfig.URL = url
	} else {
		return nil, fmt.Errorf("url is required for HTTP scanner")
	}

	if timeout, ok := config["timeout"].(string); ok {
		d, err := time.ParseDuration(timeout)
		if err == nil {
			scannerConfig.Timeout = d
		}
	}

	if headers, ok := config["headers"].(map[string]any); ok {
		scannerConfig.Headers = make(map[string]string)
		for k, v := range headers {
			if s, ok := v.(string); ok {
				scannerConfig.Headers[k] = s
			}
		}
	}

	if priority, ok := config["priority"].(int); ok {
		scannerConfig.Priority = priority
	}

	if healthEndpoint, ok := config["health_endpoint"].(string); ok {
		scannerConfig.HealthEndpoint = healthEndpoint
	}

	if scanEndpoint, ok := config["scan_endpoint"].(string); ok {
		scannerConfig.ScanEndpoint = scanEndpoint
	}

	displayName := name
	if n, ok := config["name"].(string); ok {
		displayName = n
	}

	return NewHTTPScanner(name, displayName, scannerConfig), nil
}

// RegisterHTTPScannerFactory registers the HTTP scanner factory with the global registry.
func RegisterHTTPScannerFactory() {
	factory := &HTTPScannerFactory{}
	RegisterScanner("http", func() ScannerPlugin {
		// Return a placeholder - actual instances are created via factory.Create
		return NewHTTPScanner("http", "HTTP Scanner", DefaultHTTPScannerConfig())
	})
	_ = factory // Factory is available for programmatic use
}
