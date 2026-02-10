package plugin

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
	"time"

	"github.com/brad07/ninjashield/pkg/scanners"
)

// Manager handles plugin lifecycle and coordination.
type Manager struct {
	mu sync.RWMutex

	// registry is the plugin factory registry.
	registry *Registry

	// scanners contains initialized scanner plugins.
	scanners map[string]ScannerPlugin

	// llmProviders contains initialized LLM provider plugins.
	llmProviders map[string]LLMProviderPlugin

	// pluginStates tracks the state of each plugin.
	pluginStates map[string]*PluginState

	// activeLLMProvider is the currently active LLM provider.
	activeLLMProvider string

	// config holds the manager configuration.
	config ManagerConfig

	// logger for plugin events.
	logger *log.Logger
}

// ManagerConfig contains configuration for the plugin manager.
type ManagerConfig struct {
	// HealthCheckInterval is how often to check plugin health.
	HealthCheckInterval time.Duration `yaml:"health_check_interval" json:"health_check_interval"`

	// ShutdownTimeout is the maximum time to wait for plugin shutdown.
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" json:"shutdown_timeout"`

	// FailOpen determines behavior when all plugins fail.
	// If true, allow operations to proceed. If false, deny them.
	FailOpen bool `yaml:"fail_open" json:"fail_open"`

	// ParallelScan enables parallel scanner execution.
	ParallelScan bool `yaml:"parallel_scan" json:"parallel_scan"`

	// ScannerTimeout is the maximum time for a scanner to complete.
	ScannerTimeout time.Duration `yaml:"scanner_timeout" json:"scanner_timeout"`

	// LLMTimeout is the maximum time for LLM assessment.
	LLMTimeout time.Duration `yaml:"llm_timeout" json:"llm_timeout"`
}

// DefaultManagerConfig returns a ManagerConfig with sensible defaults.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		HealthCheckInterval: 30 * time.Second,
		ShutdownTimeout:     10 * time.Second,
		FailOpen:            false,
		ParallelScan:        true,
		ScannerTimeout:      5 * time.Second,
		LLMTimeout:          30 * time.Second,
	}
}

// NewManager creates a new plugin manager.
func NewManager(registry *Registry, config ManagerConfig, logger *log.Logger) *Manager {
	if registry == nil {
		registry = GlobalRegistry()
	}
	if logger == nil {
		logger = log.Default()
	}

	return &Manager{
		registry:     registry,
		scanners:     make(map[string]ScannerPlugin),
		llmProviders: make(map[string]LLMProviderPlugin),
		pluginStates: make(map[string]*PluginState),
		config:       config,
		logger:       logger,
	}
}

// LoadScanner initializes and loads a scanner plugin.
func (m *Manager) LoadScanner(ctx context.Context, id string, config map[string]any) error {
	scanner, err := m.registry.CreateScanner(id)
	if err != nil {
		return fmt.Errorf("failed to create scanner %s: %w", id, err)
	}

	info := scanner.Info()
	m.updateState(info.ID, PluginStatusInitializing, "")

	if err := scanner.Init(ctx, config); err != nil {
		m.updateState(info.ID, PluginStatusError, err.Error())
		return fmt.Errorf("failed to initialize scanner %s: %w", id, err)
	}

	m.mu.Lock()
	m.scanners[id] = scanner
	m.mu.Unlock()

	m.updateState(info.ID, PluginStatusReady, "")
	m.logger.Printf("Loaded plugin: %s (%s)", info.ID, info.Version)

	return nil
}

// LoadLLMProvider initializes and loads an LLM provider plugin.
func (m *Manager) LoadLLMProvider(ctx context.Context, id string, config map[string]any) error {
	provider, err := m.registry.CreateLLMProvider(id)
	if err != nil {
		return fmt.Errorf("failed to create LLM provider %s: %w", id, err)
	}

	info := provider.Info()
	m.updateState(info.ID, PluginStatusInitializing, "")

	if err := provider.Init(ctx, config); err != nil {
		m.updateState(info.ID, PluginStatusError, err.Error())
		return fmt.Errorf("failed to initialize LLM provider %s: %w", id, err)
	}

	m.mu.Lock()
	m.llmProviders[id] = provider
	m.mu.Unlock()

	m.updateState(info.ID, PluginStatusReady, "")
	m.logger.Printf("Loaded plugin: %s (%s)", info.ID, info.Version)

	return nil
}

// SetActiveLLMProvider sets the active LLM provider.
func (m *Manager) SetActiveLLMProvider(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.llmProviders[id]; !exists {
		return fmt.Errorf("LLM provider not loaded: %s", id)
	}

	m.activeLLMProvider = id
	return nil
}

// GetActiveLLMProvider returns the currently active LLM provider.
func (m *Manager) GetActiveLLMProvider() (LLMProviderPlugin, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeLLMProvider == "" {
		return nil, fmt.Errorf("no active LLM provider")
	}

	provider, exists := m.llmProviders[m.activeLLMProvider]
	if !exists {
		return nil, fmt.Errorf("active LLM provider not found: %s", m.activeLLMProvider)
	}

	return provider, nil
}

// GetScanner returns a specific scanner by ID.
func (m *Manager) GetScanner(id string) (ScannerPlugin, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	scanner, exists := m.scanners[id]
	return scanner, exists
}

// GetLLMProvider returns a specific LLM provider by ID.
func (m *Manager) GetLLMProvider(id string) (LLMProviderPlugin, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	provider, exists := m.llmProviders[id]
	return provider, exists
}

// GetScanners returns all loaded scanners sorted by priority.
func (m *Manager) GetScanners() []ScannerPlugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	scanners := make([]ScannerPlugin, 0, len(m.scanners))
	for _, s := range m.scanners {
		scanners = append(scanners, s)
	}

	// Sort by priority (higher first)
	sort.Slice(scanners, func(i, j int) bool {
		return scanners[i].Priority() > scanners[j].Priority()
	})

	return scanners
}

// GetLLMProviders returns all loaded LLM providers.
func (m *Manager) GetLLMProviders() []LLMProviderPlugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	providers := make([]LLMProviderPlugin, 0, len(m.llmProviders))
	for _, p := range m.llmProviders {
		providers = append(providers, p)
	}

	return providers
}

// RunScanners executes all loaded scanners against the given request.
func (m *Manager) RunScanners(ctx context.Context, req *ScanRequest) (*AggregatedScanResponse, error) {
	loadedScanners := m.GetScanners()
	if len(loadedScanners) == 0 {
		return &AggregatedScanResponse{
			RequestID:    req.ID,
			Responses:    []*ScanResponse{},
			AllFindings:  []scanners.Finding{},
			ScannersUsed: []string{},
		}, nil
	}

	if m.config.ParallelScan {
		return m.runScannersParallel(ctx, req, loadedScanners)
	}
	return m.runScannersSequential(ctx, req, loadedScanners)
}

func (m *Manager) runScannersSequential(ctx context.Context, req *ScanRequest, scanners []ScannerPlugin) (*AggregatedScanResponse, error) {
	responses := make([]*ScanResponse, 0, len(scanners))

	for _, scanner := range scanners {
		scanCtx, cancel := context.WithTimeout(ctx, m.config.ScannerTimeout)
		resp, err := scanner.Scan(scanCtx, req)
		cancel()

		if err != nil {
			m.logger.Printf("Scanner %s failed: %v", scanner.Info().ID, err)
			m.updateState(scanner.Info().ID, PluginStatusError, err.Error())
			continue
		}

		responses = append(responses, resp)
		m.recordScanSuccess(scanner.Info().ID)
	}

	return AggregateScanResponses(req.ID, responses), nil
}

func (m *Manager) runScannersParallel(ctx context.Context, req *ScanRequest, scanners []ScannerPlugin) (*AggregatedScanResponse, error) {
	var wg sync.WaitGroup
	responseCh := make(chan *ScanResponse, len(scanners))

	for _, scanner := range scanners {
		wg.Add(1)
		go func(s ScannerPlugin) {
			defer wg.Done()

			scanCtx, cancel := context.WithTimeout(ctx, m.config.ScannerTimeout)
			defer cancel()

			resp, err := s.Scan(scanCtx, req)
			if err != nil {
				m.logger.Printf("Scanner %s failed: %v", s.Info().ID, err)
				m.updateState(s.Info().ID, PluginStatusError, err.Error())
				return
			}

			responseCh <- resp
			m.recordScanSuccess(s.Info().ID)
		}(scanner)
	}

	// Wait for all scanners and close channel
	go func() {
		wg.Wait()
		close(responseCh)
	}()

	responses := make([]*ScanResponse, 0, len(scanners))
	for resp := range responseCh {
		responses = append(responses, resp)
	}

	return AggregateScanResponses(req.ID, responses), nil
}

// AssessCommand runs AI assessment on a command using the active LLM provider.
func (m *Manager) AssessCommand(ctx context.Context, req *CommandAssessmentRequest) (*RiskAssessment, error) {
	provider, err := m.GetActiveLLMProvider()
	if err != nil {
		return nil, err
	}

	if !provider.IsAvailable(ctx) {
		return nil, fmt.Errorf("LLM provider %s is not available", provider.Info().ID)
	}

	assessCtx, cancel := context.WithTimeout(ctx, m.config.LLMTimeout)
	defer cancel()

	start := time.Now()
	assessment, err := provider.AssessCommand(assessCtx, req)
	if err != nil {
		m.updateState(provider.Info().ID, PluginStatusError, err.Error())
		return nil, err
	}

	assessment.ProcessingTimeMs = time.Since(start).Milliseconds()
	m.recordLLMSuccess(provider.Info().ID, time.Since(start))

	return assessment, nil
}

// AssessContent runs AI assessment on content using the active LLM provider.
func (m *Manager) AssessContent(ctx context.Context, req *ContentAssessmentRequest) (*RiskAssessment, error) {
	provider, err := m.GetActiveLLMProvider()
	if err != nil {
		return nil, err
	}

	if !provider.IsAvailable(ctx) {
		return nil, fmt.Errorf("LLM provider %s is not available", provider.Info().ID)
	}

	assessCtx, cancel := context.WithTimeout(ctx, m.config.LLMTimeout)
	defer cancel()

	start := time.Now()
	assessment, err := provider.AssessContent(assessCtx, req)
	if err != nil {
		m.updateState(provider.Info().ID, PluginStatusError, err.Error())
		return nil, err
	}

	assessment.ProcessingTimeMs = time.Since(start).Milliseconds()
	m.recordLLMSuccess(provider.Info().ID, time.Since(start))

	return assessment, nil
}

// Shutdown gracefully shuts down all plugins.
func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, m.config.ShutdownTimeout)
	defer cancel()

	var errs []error

	// Shutdown scanners
	for id, scanner := range m.scanners {
		m.updateStateLocked(scanner.Info().ID, PluginStatusShuttingDown, "")
		if err := scanner.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("scanner %s: %w", id, err))
		}
		m.updateStateLocked(scanner.Info().ID, PluginStatusStopped, "")
	}

	// Shutdown LLM providers
	for id, provider := range m.llmProviders {
		m.updateStateLocked(provider.Info().ID, PluginStatusShuttingDown, "")
		if err := provider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("LLM provider %s: %w", id, err))
		}
		m.updateStateLocked(provider.Info().ID, PluginStatusStopped, "")
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}

	return nil
}

// HealthCheck runs health checks on all plugins.
func (m *Manager) HealthCheck(ctx context.Context) map[string]error {
	m.mu.Lock()
	defer m.mu.Unlock()

	results := make(map[string]error)

	for id, scanner := range m.scanners {
		if err := scanner.HealthCheck(ctx); err != nil {
			results[id] = err
			m.updateStateLocked(scanner.Info().ID, PluginStatusError, err.Error())
		} else {
			m.updateStateLocked(scanner.Info().ID, PluginStatusReady, "")
		}
	}

	for id, provider := range m.llmProviders {
		if err := provider.HealthCheck(ctx); err != nil {
			results[id] = err
			m.updateStateLocked(provider.Info().ID, PluginStatusError, err.Error())
		} else {
			m.updateStateLocked(provider.Info().ID, PluginStatusReady, "")
		}
	}

	return results
}

// GetPluginStates returns the current state of all plugins.
func (m *Manager) GetPluginStates() map[string]*PluginState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	states := make(map[string]*PluginState, len(m.pluginStates))
	for k, v := range m.pluginStates {
		stateCopy := *v
		states[k] = &stateCopy
	}

	return states
}

// updateState updates the state of a plugin.
func (m *Manager) updateState(id string, status PluginStatus, lastError string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.updateStateLocked(id, status, lastError)
}

// updateStateLocked updates state without acquiring lock (caller must hold lock).
func (m *Manager) updateStateLocked(id string, status PluginStatus, lastError string) {
	state, exists := m.pluginStates[id]
	if !exists {
		state = &PluginState{}
		m.pluginStates[id] = state
	}

	state.Status = status
	state.LastError = lastError

	if status == PluginStatusReady {
		state.LastHealthCheck = time.Now()
		if state.LoadedAt.IsZero() {
			state.LoadedAt = time.Now()
		}
	}
}

// recordScanSuccess records a successful scan.
func (m *Manager) recordScanSuccess(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state, exists := m.pluginStates[id]; exists {
		state.Stats.TotalCalls++
		state.Stats.SuccessfulCalls++
	}
}

// recordLLMSuccess records a successful LLM call.
func (m *Manager) recordLLMSuccess(id string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if state, exists := m.pluginStates[id]; exists {
		state.Stats.TotalCalls++
		state.Stats.SuccessfulCalls++
		state.Stats.TotalLatencyMs += duration.Milliseconds()
		if state.Stats.TotalCalls > 0 {
			state.Stats.AverageLatencyMs = float64(state.Stats.TotalLatencyMs) / float64(state.Stats.TotalCalls)
		}
	}
}

// IsLLMAvailable checks if any LLM provider is available.
func (m *Manager) IsLLMAvailable(ctx context.Context) bool {
	provider, err := m.GetActiveLLMProvider()
	if err != nil {
		return false
	}
	return provider.IsAvailable(ctx)
}

// LoadedScannerIDs returns the IDs of all loaded scanners.
func (m *Manager) LoadedScannerIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.scanners))
	for id := range m.scanners {
		ids = append(ids, id)
	}
	return ids
}

// LoadedLLMProviderIDs returns the IDs of all loaded LLM providers.
func (m *Manager) LoadedLLMProviderIDs() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.llmProviders))
	for id := range m.llmProviders {
		ids = append(ids, id)
	}
	return ids
}

// UnloadScanner unloads and shuts down a scanner plugin.
func (m *Manager) UnloadScanner(ctx context.Context, id string) error {
	m.mu.Lock()
	scanner, exists := m.scanners[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("scanner not loaded: %s", id)
	}
	delete(m.scanners, id)
	m.mu.Unlock()

	m.updateState(scanner.Info().ID, PluginStatusShuttingDown, "")
	if err := scanner.Shutdown(ctx); err != nil {
		m.updateState(scanner.Info().ID, PluginStatusError, err.Error())
		return fmt.Errorf("failed to shutdown scanner %s: %w", id, err)
	}

	m.updateState(scanner.Info().ID, PluginStatusStopped, "")
	m.logger.Printf("Unloaded plugin: %s", scanner.Info().ID)
	return nil
}

// UnloadLLMProvider unloads and shuts down an LLM provider plugin.
func (m *Manager) UnloadLLMProvider(ctx context.Context, id string) error {
	m.mu.Lock()
	provider, exists := m.llmProviders[id]
	if !exists {
		m.mu.Unlock()
		return fmt.Errorf("LLM provider not loaded: %s", id)
	}

	// Clear active provider if this is it
	if m.activeLLMProvider == id {
		m.activeLLMProvider = ""
	}

	delete(m.llmProviders, id)
	m.mu.Unlock()

	m.updateState(provider.Info().ID, PluginStatusShuttingDown, "")
	if err := provider.Shutdown(ctx); err != nil {
		m.updateState(provider.Info().ID, PluginStatusError, err.Error())
		return fmt.Errorf("failed to shutdown LLM provider %s: %w", id, err)
	}

	m.updateState(provider.Info().ID, PluginStatusStopped, "")
	m.logger.Printf("Unloaded plugin: %s", provider.Info().ID)
	return nil
}

// HealthCheckPlugin runs a health check on a specific plugin by ID.
func (m *Manager) HealthCheckPlugin(ctx context.Context, pluginID string) error {
	m.mu.RLock()

	// Check if it's a scanner
	for id, scanner := range m.scanners {
		if id == pluginID || scanner.Info().ID == pluginID {
			m.mu.RUnlock()
			err := scanner.HealthCheck(ctx)
			if err != nil {
				m.updateState(scanner.Info().ID, PluginStatusError, err.Error())
			} else {
				m.updateState(scanner.Info().ID, PluginStatusReady, "")
			}
			return err
		}
	}

	// Check if it's an LLM provider
	for id, provider := range m.llmProviders {
		if id == pluginID || provider.Info().ID == pluginID {
			m.mu.RUnlock()
			err := provider.HealthCheck(ctx)
			if err != nil {
				m.updateState(provider.Info().ID, PluginStatusError, err.Error())
			} else {
				m.updateState(provider.Info().ID, PluginStatusReady, "")
			}
			return err
		}
	}

	m.mu.RUnlock()
	return fmt.Errorf("plugin not found: %s", pluginID)
}

// ReloadScanner reloads a scanner with new configuration.
func (m *Manager) ReloadScanner(ctx context.Context, id string, config map[string]any) error {
	// Unload existing
	if err := m.UnloadScanner(ctx, id); err != nil {
		// Ignore "not loaded" errors
		if err.Error() != fmt.Sprintf("scanner not loaded: %s", id) {
			return err
		}
	}

	// Load with new config
	return m.LoadScanner(ctx, id, config)
}

// ReloadLLMProvider reloads an LLM provider with new configuration.
func (m *Manager) ReloadLLMProvider(ctx context.Context, id string, config map[string]any) error {
	wasActive := false
	m.mu.RLock()
	if m.activeLLMProvider == id {
		wasActive = true
	}
	m.mu.RUnlock()

	// Unload existing
	if err := m.UnloadLLMProvider(ctx, id); err != nil {
		// Ignore "not loaded" errors
		if err.Error() != fmt.Sprintf("LLM provider not loaded: %s", id) {
			return err
		}
	}

	// Load with new config
	if err := m.LoadLLMProvider(ctx, id, config); err != nil {
		return err
	}

	// Restore active status
	if wasActive {
		return m.SetActiveLLMProvider(id)
	}

	return nil
}
