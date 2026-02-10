package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/brad07/ninjashield/pkg/scanners"
)

// MockScanner is a test scanner for unit tests.
type MockScanner struct {
	info       PluginInfo
	initCalled bool
	findings   []scanners.Finding
	priority   int
}

func NewMockScanner(id string, priority int, findings []scanners.Finding) *MockScanner {
	return &MockScanner{
		info: PluginInfo{
			ID:      id,
			Name:    "Mock Scanner",
			Version: "1.0.0",
			Type:    PluginTypeScanner,
			Tier:    TierCompileTime,
		},
		priority: priority,
		findings: findings,
	}
}

func (m *MockScanner) Info() PluginInfo {
	return m.info
}

func (m *MockScanner) Init(ctx context.Context, config map[string]any) error {
	m.initCalled = true
	return nil
}

func (m *MockScanner) Shutdown(ctx context.Context) error {
	return nil
}

func (m *MockScanner) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *MockScanner) Scan(ctx context.Context, req *ScanRequest) (*ScanResponse, error) {
	result := scanners.Aggregate(m.findings)
	return &ScanResponse{
		RequestID:        req.ID,
		PluginID:         m.info.ID,
		Findings:         m.findings,
		RiskScore:        result.RiskScore,
		ProcessingTimeMs: 1,
	}, nil
}

func (m *MockScanner) Priority() int {
	return m.priority
}

func (m *MockScanner) SupportedContentTypes() []string {
	return []string{}
}

// Tests

func TestPluginInfo(t *testing.T) {
	info := PluginInfo{
		ID:          "test:plugin",
		Name:        "Test Plugin",
		Version:     "1.0.0",
		Type:        PluginTypeScanner,
		Tier:        TierCompileTime,
		Description: "A test plugin",
	}

	if info.ID != "test:plugin" {
		t.Errorf("Expected ID 'test:plugin', got %s", info.ID)
	}
	if info.Type != PluginTypeScanner {
		t.Errorf("Expected type PluginTypeScanner, got %s", info.Type)
	}
}

func TestRegistry(t *testing.T) {
	registry := NewRegistry()

	// Register a scanner factory
	err := registry.RegisterScanner("mock", func() ScannerPlugin {
		return NewMockScanner("scanner:mock", 50, nil)
	})
	if err != nil {
		t.Fatalf("Failed to register scanner: %v", err)
	}

	// Try to register duplicate
	err = registry.RegisterScanner("mock", func() ScannerPlugin {
		return NewMockScanner("scanner:mock", 50, nil)
	})
	if err == nil {
		t.Error("Expected error for duplicate registration")
	}

	// Check listing
	scanners := registry.ListScanners()
	if len(scanners) != 1 || scanners[0] != "mock" {
		t.Errorf("Expected [mock], got %v", scanners)
	}

	// Create scanner
	scanner, err := registry.CreateScanner("mock")
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	if scanner.Info().ID != "scanner:mock" {
		t.Errorf("Expected scanner ID 'scanner:mock', got %s", scanner.Info().ID)
	}

	// Try to create non-existent scanner
	_, err = registry.CreateScanner("nonexistent")
	if err == nil {
		t.Error("Expected error for non-existent scanner")
	}
}

func TestManager(t *testing.T) {
	registry := NewRegistry()

	// Register mock scanner
	registry.RegisterScanner("mock", func() ScannerPlugin {
		return NewMockScanner("scanner:mock", 50, []scanners.Finding{
			{
				Type:       "test",
				Category:   "test",
				Severity:   "low",
				Confidence: 0.9,
				Message:    "Test finding",
			},
		})
	})

	config := DefaultManagerConfig()
	config.ParallelScan = false
	manager := NewManager(registry, config, nil)

	ctx := context.Background()

	// Load scanner
	err := manager.LoadScanner(ctx, "mock", nil)
	if err != nil {
		t.Fatalf("Failed to load scanner: %v", err)
	}

	// Check loaded scanners
	loadedScanners := manager.GetScanners()
	if len(loadedScanners) != 1 {
		t.Errorf("Expected 1 loaded scanner, got %d", len(loadedScanners))
	}

	// Run scanners
	req := &ScanRequest{
		ID:      "test-1",
		Content: "test content",
	}
	resp, err := manager.RunScanners(ctx, req)
	if err != nil {
		t.Fatalf("Failed to run scanners: %v", err)
	}

	if resp.RequestID != "test-1" {
		t.Errorf("Expected request ID 'test-1', got %s", resp.RequestID)
	}
	if len(resp.AllFindings) != 1 {
		t.Errorf("Expected 1 finding, got %d", len(resp.AllFindings))
	}
	if len(resp.ScannersUsed) != 1 {
		t.Errorf("Expected 1 scanner used, got %d", len(resp.ScannersUsed))
	}

	// Shutdown
	err = manager.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}
}

func TestManagerParallelScan(t *testing.T) {
	registry := NewRegistry()

	// Register multiple mock scanners
	registry.RegisterScanner("mock1", func() ScannerPlugin {
		return NewMockScanner("scanner:mock1", 100, []scanners.Finding{
			{Type: "test1", Category: "test", Severity: "high", Confidence: 0.9, Message: "Test 1"},
		})
	})
	registry.RegisterScanner("mock2", func() ScannerPlugin {
		return NewMockScanner("scanner:mock2", 50, []scanners.Finding{
			{Type: "test2", Category: "test", Severity: "low", Confidence: 0.8, Message: "Test 2"},
		})
	})

	config := DefaultManagerConfig()
	config.ParallelScan = true
	manager := NewManager(registry, config, nil)

	ctx := context.Background()

	// Load scanners
	manager.LoadScanner(ctx, "mock1", nil)
	manager.LoadScanner(ctx, "mock2", nil)

	req := &ScanRequest{
		ID:      "test-parallel",
		Content: "test content",
	}
	resp, err := manager.RunScanners(ctx, req)
	if err != nil {
		t.Fatalf("Failed to run scanners: %v", err)
	}

	if len(resp.AllFindings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(resp.AllFindings))
	}
	if len(resp.ScannersUsed) != 2 {
		t.Errorf("Expected 2 scanners used, got %d", len(resp.ScannersUsed))
	}
	// High severity should give higher risk score
	if resp.AggregatedRiskScore != 75 {
		t.Errorf("Expected aggregated risk score 75, got %d", resp.AggregatedRiskScore)
	}
}

func TestAggregateScanResponses(t *testing.T) {
	responses := []*ScanResponse{
		{
			RequestID:        "test-1",
			PluginID:         "scanner:secrets",
			Findings:         []scanners.Finding{{Type: "api_key", Category: "secrets", Severity: "critical"}},
			RiskScore:        100,
			ProcessingTimeMs: 10,
		},
		{
			RequestID:        "test-1",
			PluginID:         "scanner:pii",
			Findings:         []scanners.Finding{{Type: "email", Category: "pii", Severity: "medium"}},
			RiskScore:        50,
			ProcessingTimeMs: 5,
		},
	}

	agg := AggregateScanResponses("test-1", responses)

	if agg.RequestID != "test-1" {
		t.Errorf("Expected request ID 'test-1', got %s", agg.RequestID)
	}
	if len(agg.AllFindings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(agg.AllFindings))
	}
	if agg.AggregatedRiskScore != 100 {
		t.Errorf("Expected aggregated risk score 100, got %d", agg.AggregatedRiskScore)
	}
	if agg.HighestSeverity != "critical" {
		t.Errorf("Expected highest severity 'critical', got %s", agg.HighestSeverity)
	}
	if agg.TotalProcessingTimeMs != 15 {
		t.Errorf("Expected total processing time 15ms, got %d", agg.TotalProcessingTimeMs)
	}
	if len(agg.ContentClasses) != 2 {
		t.Errorf("Expected 2 content classes, got %d", len(agg.ContentClasses))
	}
}

func TestDefaultPluginConfig(t *testing.T) {
	cfg := DefaultPluginConfig("test:plugin", PluginTypeScanner)

	if cfg.ID != "test:plugin" {
		t.Errorf("Expected ID 'test:plugin', got %s", cfg.ID)
	}
	if !cfg.Enabled {
		t.Error("Expected plugin to be enabled by default")
	}
	if cfg.Priority != 50 {
		t.Errorf("Expected priority 50, got %d", cfg.Priority)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", cfg.Timeout)
	}
}

func TestPluginStates(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterScanner("mock", func() ScannerPlugin {
		return NewMockScanner("scanner:mock", 50, nil)
	})

	manager := NewManager(registry, DefaultManagerConfig(), nil)
	ctx := context.Background()

	// Load scanner
	manager.LoadScanner(ctx, "mock", nil)

	// Check states
	states := manager.GetPluginStates()
	state, exists := states["scanner:mock"]
	if !exists {
		t.Fatal("Expected state for scanner:mock")
	}
	if state.Status != PluginStatusReady {
		t.Errorf("Expected status Ready, got %s", state.Status)
	}
}
