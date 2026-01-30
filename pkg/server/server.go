// Package server implements the NinjaShield HTTP server.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/brad07/ninjashield/pkg/api"
	"github.com/brad07/ninjashield/pkg/llm"
	"github.com/brad07/ninjashield/pkg/policy"
	"github.com/brad07/ninjashield/pkg/storage"
)

// Config holds server configuration.
type Config struct {
	Host            string
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

// DefaultConfig returns the default server configuration.
func DefaultConfig() Config {
	return Config{
		Host:            "localhost",
		Port:            7575,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		ShutdownTimeout: 10 * time.Second,
	}
}

// Server represents the NinjaShield HTTP server.
type Server struct {
	config     Config
	httpServer *http.Server
	engine     *policy.Engine
	llmEngine  *llm.Engine
	store      storage.Store
	startTime  time.Time
	listener   net.Listener

	mu      sync.RWMutex
	running bool
}

// New creates a new server with the given configuration.
func New(config Config, engine *policy.Engine, store storage.Store) *Server {
	return &Server{
		config: config,
		engine: engine,
		store:  store,
	}
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("server already running")
	}
	s.running = true
	s.startTime = time.Now()
	s.mu.Unlock()

	mux := http.NewServeMux()
	s.registerRoutes(mux)

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = listener

	log.Printf("Server listening on http://%s", listener.Addr().String())

	go func() {
		if err := s.httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the HTTP server.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
	defer cancel()

	log.Println("Shutting down server...")
	return s.httpServer.Shutdown(ctx)
}

// IsRunning returns true if the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Addr returns the actual address the server is listening on.
// This is useful when the server was started with port 0 (random port).
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
}

// GetEngine returns the policy engine.
func (s *Server) GetEngine() *policy.Engine {
	return s.engine
}

// SetEngine updates the policy engine.
func (s *Server) SetEngine(engine *policy.Engine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engine = engine
}

// GetLLMEngine returns the LLM engine.
func (s *Server) GetLLMEngine() *llm.Engine {
	return s.llmEngine
}

// SetLLMEngine sets the LLM evaluation engine.
func (s *Server) SetLLMEngine(engine *llm.Engine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.llmEngine = engine
}

// registerRoutes registers all API routes.
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health check
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /ready", s.handleReady)

	// API v1 - Command evaluation
	mux.HandleFunc("POST /v1/commands/evaluate", s.handleEvaluateCommand)
	mux.HandleFunc("GET /v1/policy", s.handleGetPolicy)
	mux.HandleFunc("PUT /v1/policy", s.handleUpdatePolicy)
	mux.HandleFunc("GET /v1/stats", s.handleGetStats)

	// API v1 - LLM evaluation
	mux.HandleFunc("POST /v1/llm/evaluate", s.handleEvaluateLLM)
}

// loggingMiddleware logs all requests.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		log.Printf("%s %s %d %s",
			r.Method,
			r.URL.Path,
			rw.statusCode,
			time.Since(start),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleHealth handles health check requests.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	api.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "healthy",
	})
}

// handleReady handles readiness check requests.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.engine == nil {
		api.WriteError(w, http.StatusServiceUnavailable, "not_ready", "Policy engine not initialized")
		return
	}
	api.WriteJSON(w, http.StatusOK, map[string]string{
		"status": "ready",
	})
}

// handleEvaluateCommand handles command evaluation requests.
func (s *Server) handleEvaluateCommand(w http.ResponseWriter, r *http.Request) {
	var req api.CommandEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid_json", "Failed to parse request body")
		return
	}

	if req.Command == "" {
		api.WriteError(w, http.StatusBadRequest, "missing_command", "Command is required")
		return
	}

	// Evaluate command using the policy engine
	result := s.engine.EvaluateCommandWithContext(
		req.Command,
		req.Cwd,
		req.RepoRoot,
		req.User,
		req.Tool,
	)

	// Record audit event
	if s.store != nil {
		event := storage.AuditEvent{
			Timestamp:      time.Now(),
			Command:        req.Command,
			Decision:       string(result.Decision),
			RiskScore:      result.RiskScore,
			RiskCategories: result.RiskCategories,
			PolicyID:       result.PolicyID,
			MatchedRules:   result.MatchedRules,
			Tool:           req.Tool,
			User:           req.User,
			Cwd:            req.Cwd,
		}
		if err := s.store.RecordAudit(event); err != nil {
			log.Printf("Failed to record audit event: %v", err)
		}
	}

	// Build response
	resp := api.CommandEvaluateResponse{
		Decision:       string(result.Decision),
		RiskScore:      result.RiskScore,
		RiskCategories: result.RiskCategories,
		ReasonCodes:    result.ReasonCodes,
		PolicyID:       result.PolicyID,
		Context:        result.Context,
	}

	if result.Rewrite != nil {
		resp.Rewrite = &api.Rewrite{
			Suggested: result.Rewrite.Suggested,
			Reason:    result.Rewrite.Reason,
		}
	}

	api.WriteJSON(w, http.StatusOK, resp)
}

// handleGetPolicy handles get policy requests.
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	pol := s.engine.GetPolicy()

	scannersEnabled := []string{}
	// Check which scanners are enabled based on engine config
	// For now, we assume all are enabled
	scannersEnabled = append(scannersEnabled, "secrets", "pii", "commands")

	resp := api.PolicyResponse{
		ActivePack:      pol.ID,
		Version:         pol.Version,
		RulesCount:      len(pol.Rules),
		ScannersEnabled: scannersEnabled,
		LastUpdated:     time.Now().Format(time.RFC3339),
	}

	api.WriteJSON(w, http.StatusOK, resp)
}

// UpdatePolicyRequest represents a policy update request.
type UpdatePolicyRequest struct {
	Pack string `json:"pack"`
}

// handleUpdatePolicy handles policy update requests.
func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var req UpdatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid_json", "Failed to parse request body")
		return
	}

	if req.Pack == "" {
		api.WriteError(w, http.StatusBadRequest, "missing_pack", "Pack name is required")
		return
	}

	// Validate pack name (this would be done by the caller)
	api.WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "updated",
		"pack":    req.Pack,
		"message": "Policy update queued",
	})
}

// StatsResponse represents server statistics.
type StatsResponse struct {
	Uptime         string `json:"uptime"`
	RequestsTotal  int64  `json:"requests_total"`
	EvaluationsDay int64  `json:"evaluations_today"`
	PolicyID       string `json:"policy_id"`
}

// handleGetStats handles stats requests.
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime)

	var evalsToday int64
	if s.store != nil {
		evalsToday, _ = s.store.CountAuditsToday()
	}

	resp := StatsResponse{
		Uptime:         uptime.Round(time.Second).String(),
		EvaluationsDay: evalsToday,
		PolicyID:       s.engine.GetPolicy().ID,
	}

	api.WriteJSON(w, http.StatusOK, resp)
}

// LLMEvaluateRequest represents an LLM evaluation request.
type LLMEvaluateRequest struct {
	// Provider is the LLM provider (openai, anthropic, etc.)
	Provider string `json:"provider,omitempty"`
	// TargetURL is the URL being called (used for provider detection if provider not specified)
	TargetURL string `json:"target_url,omitempty"`
	// Body is the raw request body to the LLM API
	Body json.RawMessage `json:"body"`
	// User is the user making the request
	User string `json:"user,omitempty"`
	// Tool is the tool making the request
	Tool string `json:"tool,omitempty"`
}

// LLMEvaluateResponse represents an LLM evaluation response.
type LLMEvaluateResponse struct {
	Decision       string        `json:"decision"`
	RiskScore      int           `json:"risk_score"`
	RiskCategories []string      `json:"risk_categories"`
	ReasonCodes    []string      `json:"reason_codes,omitempty"`
	Reasons        []string      `json:"reasons,omitempty"`
	PolicyID       string        `json:"policy_id"`
	MatchedRules   []string      `json:"matched_rules,omitempty"`
	Context        string        `json:"context,omitempty"`
	Redactions     []LLMRedaction `json:"redactions,omitempty"`
}

// LLMRedaction represents a redaction to apply.
type LLMRedaction struct {
	Field       string `json:"field"`
	Type        string `json:"type"`
	Replacement string `json:"replacement"`
	Reason      string `json:"reason"`
}

// handleEvaluateLLM handles LLM request evaluation.
func (s *Server) handleEvaluateLLM(w http.ResponseWriter, r *http.Request) {
	// Check if LLM engine is configured
	if s.llmEngine == nil {
		api.WriteError(w, http.StatusServiceUnavailable, "llm_not_configured", "LLM evaluation engine not configured")
		return
	}

	// Read and parse request
	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "read_error", "Failed to read request body")
		return
	}

	var req LLMEvaluateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		api.WriteError(w, http.StatusBadRequest, "invalid_json", "Failed to parse request body")
		return
	}

	if len(req.Body) == 0 {
		api.WriteError(w, http.StatusBadRequest, "missing_body", "LLM request body is required")
		return
	}

	// Detect provider if not specified
	provider := llm.Provider(req.Provider)
	if provider == "" && req.TargetURL != "" {
		providerInfo := llm.DetectProvider(req.TargetURL)
		provider = providerInfo.Provider
	}
	if provider == "" {
		provider = llm.ProviderUnknown
	}

	// Parse the LLM request
	parser := llm.NewParser()
	llmReq, err := parser.ParseRequest(provider, req.TargetURL, req.Body)
	if err != nil {
		api.WriteError(w, http.StatusBadRequest, "parse_error", fmt.Sprintf("Failed to parse LLM request: %v", err))
		return
	}

	// Set user and tool context
	llmReq.User = req.User
	llmReq.Tool = req.Tool

	// Evaluate the request
	result := s.llmEngine.Evaluate(r.Context(), llmReq)

	// Record audit event
	if s.store != nil {
		event := storage.AuditEvent{
			Timestamp:      time.Now(),
			Command:        fmt.Sprintf("LLM:%s/%s", provider, llmReq.Model),
			Decision:       result.Decision,
			RiskScore:      result.RiskScore,
			RiskCategories: result.RiskCategories,
			PolicyID:       result.PolicyID,
			MatchedRules:   result.MatchedRules,
			Tool:           req.Tool,
			User:           req.User,
		}
		if err := s.store.RecordAudit(event); err != nil {
			log.Printf("Failed to record audit event: %v", err)
		}
	}

	// Build response
	resp := LLMEvaluateResponse{
		Decision:       result.Decision,
		RiskScore:      result.RiskScore,
		RiskCategories: result.RiskCategories,
		ReasonCodes:    result.ReasonCodes,
		Reasons:        result.Reasons,
		PolicyID:       result.PolicyID,
		MatchedRules:   result.MatchedRules,
		Context:        result.Context,
	}

	// Add redactions if any
	for _, red := range result.Redactions {
		resp.Redactions = append(resp.Redactions, LLMRedaction{
			Field:       red.Field,
			Type:        red.Type,
			Replacement: red.Replacement,
			Reason:      red.Reason,
		})
	}

	api.WriteJSON(w, http.StatusOK, resp)
}
