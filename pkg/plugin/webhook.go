// Package plugin provides the plugin system for NinjaShield.
package plugin

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebhookHandler manages HTTP webhooks for integration plugins.
type WebhookHandler struct {
	mu           sync.RWMutex
	integrations map[string]IntegrationPlugin
	pipeline     *Pipeline
	logger       *log.Logger
	mux          *http.ServeMux
}

// NewWebhookHandler creates a new webhook handler.
func NewWebhookHandler(pipeline *Pipeline, logger *log.Logger) *WebhookHandler {
	if logger == nil {
		logger = log.Default()
	}

	h := &WebhookHandler{
		integrations: make(map[string]IntegrationPlugin),
		pipeline:     pipeline,
		logger:       logger,
		mux:          http.NewServeMux(),
	}

	// Register default routes
	h.mux.HandleFunc("/webhooks/", h.handleWebhook)
	h.mux.HandleFunc("/webhooks/health", h.handleHealth)

	return h
}

// RegisterIntegration registers an integration plugin for webhook handling.
func (h *WebhookHandler) RegisterIntegration(integration IntegrationPlugin) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	info := integration.Info()
	id := strings.TrimPrefix(info.ID, "integration:")

	// Set the pipeline on the integration if it supports it
	if base, ok := integration.(interface{ SetPipeline(*Pipeline) }); ok {
		base.SetPipeline(h.pipeline)
	}

	h.integrations[id] = integration
	h.logger.Printf("Registered webhook integration: %s", id)

	return nil
}

// UnregisterIntegration removes an integration from webhook handling.
func (h *WebhookHandler) UnregisterIntegration(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	delete(h.integrations, id)
	h.logger.Printf("Unregistered webhook integration: %s", id)
}

// GetIntegration returns a registered integration by ID.
func (h *WebhookHandler) GetIntegration(id string) (IntegrationPlugin, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	integration, exists := h.integrations[id]
	return integration, exists
}

// Handler returns the HTTP handler for webhooks.
func (h *WebhookHandler) Handler() http.Handler {
	return h.mux
}

// handleHealth handles health check requests.
func (h *WebhookHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":       "ok",
		"integrations": len(h.integrations),
	})
}

// handleWebhook handles incoming webhook requests.
func (h *WebhookHandler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract integration ID from path: /webhooks/{integration_id}
	path := strings.TrimPrefix(r.URL.Path, "/webhooks/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Integration ID required", http.StatusBadRequest)
		return
	}

	integrationID := parts[0]

	// Find the integration
	integration, exists := h.GetIntegration(integrationID)
	if !exists {
		http.Error(w, fmt.Sprintf("Integration not found: %s", integrationID), http.StatusNotFound)
		return
	}

	// Read request body
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Verify webhook signature if configured
	if configurable, ok := integration.(interface{ Config() IntegrationConfig }); ok {
		cfg := configurable.Config()
		if cfg.WebhookSecret != "" {
			signature := r.Header.Get("X-Webhook-Signature")
			if signature == "" {
				signature = r.Header.Get("X-Hub-Signature-256")
			}
			if !h.verifySignature(body, signature, cfg.WebhookSecret) {
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
				return
			}
		}
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Handle the request
	response, err := integration.HandleRequest(ctx, body)
	if err != nil {
		h.logger.Printf("Integration %s error: %v", integrationID, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Send response
	w.Header().Set("Content-Type", "application/json")
	if !response.Allowed {
		w.WriteHeader(http.StatusForbidden)
	}
	json.NewEncoder(w).Encode(response)
}

// verifySignature verifies an HMAC-SHA256 webhook signature.
func (h *WebhookHandler) verifySignature(payload []byte, signature, secret string) bool {
	if signature == "" {
		return false
	}

	// Handle "sha256=" prefix
	signature = strings.TrimPrefix(signature, "sha256=")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedMAC := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(signature), []byte(expectedMAC))
}

// WebhookClient is a client for sending webhook requests to external services.
type WebhookClient struct {
	client  *http.Client
	baseURL string
	secret  string
	headers map[string]string
}

// WebhookClientConfig holds configuration for a webhook client.
type WebhookClientConfig struct {
	URL     string
	Secret  string
	Timeout time.Duration
	Headers map[string]string
}

// NewWebhookClient creates a new webhook client.
func NewWebhookClient(config WebhookClientConfig) *WebhookClient {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &WebhookClient{
		client: &http.Client{
			Timeout: timeout,
		},
		baseURL: config.URL,
		secret:  config.Secret,
		headers: config.Headers,
	}
}

// Send sends a webhook notification.
func (c *WebhookClient) Send(ctx context.Context, event string, payload any) error {
	body, err := json.Marshal(map[string]any{
		"event":     event,
		"payload":   payload,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add signature if secret is configured
	if c.secret != "" {
		mac := hmac.New(sha256.New, []byte(c.secret))
		mac.Write(body)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Webhook-Signature", "sha256="+signature)
	}

	// Add custom headers
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// IntegrationRouter routes requests to the appropriate integration handler.
type IntegrationRouter struct {
	handler *WebhookHandler
}

// NewIntegrationRouter creates a new integration router.
func NewIntegrationRouter(handler *WebhookHandler) *IntegrationRouter {
	return &IntegrationRouter{
		handler: handler,
	}
}

// Route processes an integration request and returns the response.
func (r *IntegrationRouter) Route(ctx context.Context, integrationID string, payload []byte) (*IntegrationResponse, error) {
	integration, exists := r.handler.GetIntegration(integrationID)
	if !exists {
		return nil, fmt.Errorf("integration not found: %s", integrationID)
	}

	return integration.HandleRequest(ctx, payload)
}

// RouteRequest processes a pre-parsed integration request.
func (r *IntegrationRouter) RouteRequest(ctx context.Context, req *IntegrationRequest) (*IntegrationResponse, error) {
	integration, exists := r.handler.GetIntegration(req.IntegrationID)
	if !exists {
		return nil, fmt.Errorf("integration not found: %s", req.IntegrationID)
	}

	// Get the pipeline
	var pipeline *Pipeline
	if p, ok := integration.(interface{ GetPipeline() *Pipeline }); ok {
		pipeline = p.GetPipeline()
	}

	if pipeline == nil {
		return nil, fmt.Errorf("no pipeline configured for integration: %s", req.IntegrationID)
	}

	// Build pipeline request
	pipelineReq := &PipelineRequest{
		ID:          req.ID,
		Command:     req.Payload.Command,
		ContentType: req.Payload.ContentType,
		Context: PipelineContext{
			Source:           req.IntegrationID,
			User:             req.Context.User,
			SessionID:        req.Context.SessionID,
			WorkingDirectory: req.Context.WorkingDirectory,
		},
	}

	// If no command but has content, use that
	if pipelineReq.Command == "" && req.Payload.Content != "" {
		pipelineReq.Command = req.Payload.Content
	}

	// Evaluate through pipeline
	pipelineResp, err := pipeline.EvaluateCommand(ctx, pipelineReq)
	if err != nil {
		return nil, fmt.Errorf("pipeline evaluation failed: %w", err)
	}

	// Format response
	return integration.FormatResponse(ctx, req, pipelineResp)
}
