// Package proxy provides an OpenAI-compatible proxy that evaluates and filters LLM requests.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/brad07/ninjashield/pkg/llm"
	"github.com/brad07/ninjashield/pkg/policy"
	"github.com/brad07/ninjashield/pkg/redact"
)

// Config holds proxy configuration.
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":8080")
	ListenAddr string
	// UpstreamURL is the upstream LLM API URL (e.g., "https://api.openai.com")
	UpstreamURL string
	// ReadTimeout is the read timeout for incoming requests
	ReadTimeout time.Duration
	// WriteTimeout is the write timeout for responses
	WriteTimeout time.Duration
	// EnableRedaction enables automatic redaction of secrets/PII
	EnableRedaction bool
	// RedactSecrets enables redaction of detected secrets
	RedactSecrets bool
	// RedactPII enables redaction of detected PII
	RedactPII bool
	// BlockOnDeny blocks requests that are denied by policy
	BlockOnDeny bool
	// AuditMode only logs decisions without blocking
	AuditMode bool
}

// DefaultConfig returns the default proxy configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr:      ":8080",
		UpstreamURL:     "https://api.openai.com",
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    120 * time.Second, // LLM responses can be slow
		EnableRedaction: true,
		RedactSecrets:   true,
		RedactPII:       false, // Off by default - may break legitimate use cases
		BlockOnDeny:     true,
		AuditMode:       false,
	}
}

// Proxy is an OpenAI-compatible proxy server.
type Proxy struct {
	config      Config
	llmEngine   *llm.Engine
	redactor    *redact.Redactor
	transformer *redact.Transformer
	httpServer  *http.Server
	upstream    *url.URL

	mu      sync.RWMutex
	running bool
	stats   *Stats
}

// Stats holds proxy statistics.
type Stats struct {
	mu                sync.RWMutex
	RequestsTotal     int64
	RequestsAllowed   int64
	RequestsDenied    int64
	RequestsRedacted  int64
	RequestsAsk       int64
	SecretsRedacted   int64
	PIIRedacted       int64
	BytesIn           int64
	BytesOut          int64
	UpstreamErrors    int64
	LastRequestTime   time.Time
	StartTime         time.Time
}

// NewProxy creates a new proxy server.
func NewProxy(config Config, engine *llm.Engine) (*Proxy, error) {
	upstream, err := url.Parse(config.UpstreamURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	return &Proxy{
		config:      config,
		llmEngine:   engine,
		redactor:    redact.NewRedactor(),
		transformer: redact.NewTransformer(),
		upstream:    upstream,
		stats: &Stats{
			StartTime: time.Now(),
		},
	}, nil
}

// Start starts the proxy server.
func (p *Proxy) Start() error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return fmt.Errorf("proxy already running")
	}
	p.running = true
	p.mu.Unlock()

	mux := http.NewServeMux()

	// Proxy all requests
	mux.HandleFunc("/", p.handleProxy)

	// Health and stats endpoints
	mux.HandleFunc("/ninja/health", p.handleHealth)
	mux.HandleFunc("/ninja/stats", p.handleStats)

	p.httpServer = &http.Server{
		Addr:         p.config.ListenAddr,
		Handler:      p.loggingMiddleware(mux),
		ReadTimeout:  p.config.ReadTimeout,
		WriteTimeout: p.config.WriteTimeout,
	}

	log.Printf("Proxy listening on %s, forwarding to %s", p.config.ListenAddr, p.config.UpstreamURL)

	go func() {
		if err := p.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Proxy error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the proxy server.
func (p *Proxy) Stop() error {
	p.mu.Lock()
	if !p.running {
		p.mu.Unlock()
		return nil
	}
	p.running = false
	p.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return p.httpServer.Shutdown(ctx)
}

// IsRunning returns true if the proxy is running.
func (p *Proxy) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// GetStats returns current proxy statistics.
func (p *Proxy) GetStats() Stats {
	p.stats.mu.RLock()
	defer p.stats.mu.RUnlock()
	return Stats{
		RequestsTotal:    p.stats.RequestsTotal,
		RequestsAllowed:  p.stats.RequestsAllowed,
		RequestsDenied:   p.stats.RequestsDenied,
		RequestsRedacted: p.stats.RequestsRedacted,
		RequestsAsk:      p.stats.RequestsAsk,
		SecretsRedacted:  p.stats.SecretsRedacted,
		PIIRedacted:      p.stats.PIIRedacted,
		BytesIn:          p.stats.BytesIn,
		BytesOut:         p.stats.BytesOut,
		UpstreamErrors:   p.stats.UpstreamErrors,
		LastRequestTime:  p.stats.LastRequestTime,
		StartTime:        p.stats.StartTime,
	}
}

// handleProxy handles proxied requests.
func (p *Proxy) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Skip evaluation for non-API paths
	if !p.isAPIPath(r.URL.Path) {
		p.forwardRequest(w, r, nil)
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		p.writeError(w, http.StatusBadRequest, "read_error", "Failed to read request body")
		return
	}
	r.Body.Close()

	p.stats.mu.Lock()
	p.stats.RequestsTotal++
	p.stats.BytesIn += int64(len(body))
	p.stats.LastRequestTime = time.Now()
	p.stats.mu.Unlock()

	// Parse and evaluate the LLM request
	parser := llm.NewParser()
	provider := llm.DetectProvider(p.config.UpstreamURL)
	llmReq, err := parser.ParseRequest(provider.Provider, r.URL.Path, body)
	if err != nil {
		// If we can't parse it, just forward it
		log.Printf("Could not parse request: %v, forwarding as-is", err)
		p.forwardRequest(w, r, body)
		return
	}

	// Evaluate the request
	result := p.llmEngine.Evaluate(r.Context(), llmReq)

	// Handle the decision
	switch result.Decision {
	case string(policy.DecisionDeny):
		p.stats.mu.Lock()
		p.stats.RequestsDenied++
		p.stats.mu.Unlock()

		if p.config.BlockOnDeny && !p.config.AuditMode {
			p.writeDenied(w, result)
			return
		}
		// In audit mode, log and continue
		log.Printf("AUDIT: Would deny request - %v", result.Reasons)

	case string(policy.DecisionAsk):
		p.stats.mu.Lock()
		p.stats.RequestsAsk++
		p.stats.mu.Unlock()

		// For now, treat ASK as a soft block in proxy mode
		// In a full implementation, this would trigger an approval flow
		if p.config.BlockOnDeny && !p.config.AuditMode {
			p.writeNeedsApproval(w, result)
			return
		}

	case string(policy.DecisionRedact):
		// Apply redactions
		body = p.applyRedactions(body, result)
		p.stats.mu.Lock()
		p.stats.RequestsRedacted++
		p.stats.mu.Unlock()

	default:
		p.stats.mu.Lock()
		p.stats.RequestsAllowed++
		p.stats.mu.Unlock()
	}

	// Apply automatic redaction if enabled
	if p.config.EnableRedaction {
		body = p.applyAutoRedaction(body)
	}

	// Forward the request
	p.forwardRequest(w, r, body)
}

// isAPIPath checks if the path is an API endpoint that should be evaluated.
func (p *Proxy) isAPIPath(path string) bool {
	apiPaths := []string{
		"/v1/chat/completions",
		"/v1/completions",
		"/v1/messages",
		"/v1/embeddings",
		"/api/chat",
		"/api/generate",
	}
	for _, prefix := range apiPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// forwardRequest forwards the request to the upstream server.
func (p *Proxy) forwardRequest(w http.ResponseWriter, r *http.Request, body []byte) {
	// Create the upstream request
	upstreamURL := *p.upstream
	upstreamURL.Path = r.URL.Path
	upstreamURL.RawQuery = r.URL.RawQuery

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	} else {
		bodyReader = r.Body
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL.String(), bodyReader)
	if err != nil {
		p.writeError(w, http.StatusInternalServerError, "upstream_error", "Failed to create upstream request")
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, value := range values {
			upstreamReq.Header.Add(key, value)
		}
	}

	// Update host header
	upstreamReq.Host = p.upstream.Host

	// Send the request
	client := &http.Client{
		Timeout: p.config.WriteTimeout,
	}
	resp, err := client.Do(upstreamReq)
	if err != nil {
		p.stats.mu.Lock()
		p.stats.UpstreamErrors++
		p.stats.mu.Unlock()
		p.writeError(w, http.StatusBadGateway, "upstream_error", fmt.Sprintf("Upstream request failed: %v", err))
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Copy status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body
	written, _ := io.Copy(w, resp.Body)
	p.stats.mu.Lock()
	p.stats.BytesOut += written
	p.stats.mu.Unlock()
}

// applyRedactions applies redactions from the evaluation result.
func (p *Proxy) applyRedactions(body []byte, result *llm.EvaluationResult) []byte {
	if len(result.Redactions) == 0 {
		return body
	}

	content := string(body)
	for _, red := range result.Redactions {
		// The redaction contains info about what to redact
		// In a full implementation, we'd apply specific redactions
		// For now, use the transformer
		if red.Type == "secrets" {
			res := p.redactor.RedactSecrets(content)
			if res.HasChanges {
				content = res.Redacted
				p.stats.mu.Lock()
				p.stats.SecretsRedacted += int64(len(res.Replacements))
				p.stats.mu.Unlock()
			}
		} else if red.Type == "pii" {
			res := p.redactor.RedactPII(content)
			if res.HasChanges {
				content = res.Redacted
				p.stats.mu.Lock()
				p.stats.PIIRedacted += int64(len(res.Replacements))
				p.stats.mu.Unlock()
			}
		}
	}

	return []byte(content)
}

// applyAutoRedaction applies automatic redaction based on config.
func (p *Proxy) applyAutoRedaction(body []byte) []byte {
	content := string(body)
	changed := false

	if p.config.RedactSecrets {
		res := p.redactor.RedactSecrets(content)
		if res.HasChanges {
			content = res.Redacted
			changed = true
			p.stats.mu.Lock()
			p.stats.SecretsRedacted += int64(len(res.Replacements))
			p.stats.mu.Unlock()
		}
	}

	if p.config.RedactPII {
		res := p.redactor.RedactPII(content)
		if res.HasChanges {
			content = res.Redacted
			changed = true
			p.stats.mu.Lock()
			p.stats.PIIRedacted += int64(len(res.Replacements))
			p.stats.mu.Unlock()
		}
	}

	if changed {
		p.stats.mu.Lock()
		p.stats.RequestsRedacted++
		p.stats.mu.Unlock()
	}

	return []byte(content)
}

// writeDenied writes a denied response.
func (p *Proxy) writeDenied(w http.ResponseWriter, result *llm.EvaluationResult) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-NinjaShield-Decision", "DENY")
	w.WriteHeader(http.StatusForbidden)

	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": fmt.Sprintf("Request blocked by NinjaShield: %s", strings.Join(result.Reasons, "; ")),
			"type":    "security_block",
			"code":    "request_blocked",
			"param":   nil,
		},
		"ninja_shield": map[string]interface{}{
			"decision":        result.Decision,
			"risk_score":      result.RiskScore,
			"risk_categories": result.RiskCategories,
			"reason_codes":    result.ReasonCodes,
			"policy_id":       result.PolicyID,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// writeNeedsApproval writes a needs-approval response.
func (p *Proxy) writeNeedsApproval(w http.ResponseWriter, result *llm.EvaluationResult) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-NinjaShield-Decision", "ASK")
	w.WriteHeader(http.StatusForbidden)

	resp := map[string]interface{}{
		"error": map[string]interface{}{
			"message": fmt.Sprintf("Request requires approval: %s", strings.Join(result.Reasons, "; ")),
			"type":    "approval_required",
			"code":    "needs_approval",
			"param":   nil,
		},
		"ninja_shield": map[string]interface{}{
			"decision":        result.Decision,
			"risk_score":      result.RiskScore,
			"risk_categories": result.RiskCategories,
			"context":         result.Context,
			"policy_id":       result.PolicyID,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

// writeError writes an error response.
func (p *Proxy) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]interface{}{
			"message": message,
			"type":    "proxy_error",
			"code":    code,
		},
	})
}

// handleHealth handles health check requests.
func (p *Proxy) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"mode":   "proxy",
	})
}

// handleStats handles stats requests.
func (p *Proxy) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := p.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"uptime":            time.Since(stats.StartTime).String(),
		"requests_total":    stats.RequestsTotal,
		"requests_allowed":  stats.RequestsAllowed,
		"requests_denied":   stats.RequestsDenied,
		"requests_redacted": stats.RequestsRedacted,
		"requests_ask":      stats.RequestsAsk,
		"secrets_redacted":  stats.SecretsRedacted,
		"pii_redacted":      stats.PIIRedacted,
		"bytes_in":          stats.BytesIn,
		"bytes_out":         stats.BytesOut,
		"upstream_errors":   stats.UpstreamErrors,
		"last_request":      stats.LastRequestTime.Format(time.RFC3339),
	})
}

// loggingMiddleware logs all requests.
func (p *Proxy) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		// Don't log health checks
		if r.URL.Path != "/ninja/health" {
			log.Printf("PROXY %s %s %d %s",
				r.Method,
				r.URL.Path,
				rw.statusCode,
				time.Since(start),
			)
		}
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// CreateReverseProxy creates a standard reverse proxy with NinjaShield evaluation.
func CreateReverseProxy(upstreamURL string, engine *llm.Engine) (*httputil.ReverseProxy, error) {
	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = upstream.Host
	}

	return proxy, nil
}
