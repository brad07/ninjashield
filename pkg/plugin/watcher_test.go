package plugin

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherConfig(t *testing.T) {
	cfg := DefaultWatcherConfig()

	if cfg.DebounceInterval != 500*time.Millisecond {
		t.Errorf("Expected debounce interval 500ms, got %v", cfg.DebounceInterval)
	}

	if cfg.OnError == nil {
		t.Error("Expected default OnError handler")
	}
}

func TestHealthMonitorConfig(t *testing.T) {
	cfg := DefaultHealthMonitorConfig()

	if cfg.CheckInterval != 30*time.Second {
		t.Errorf("Expected check interval 30s, got %v", cfg.CheckInterval)
	}

	if cfg.MaxRetries != 3 {
		t.Errorf("Expected max retries 3, got %d", cfg.MaxRetries)
	}

	if cfg.RetryDelay != 5*time.Second {
		t.Errorf("Expected retry delay 5s, got %v", cfg.RetryDelay)
	}
}

func TestReloadManagerIsReloading(t *testing.T) {
	registry := NewRegistry()
	manager := NewManager(registry, DefaultManagerConfig(), nil)
	reloadMgr := NewReloadManager(manager)

	if reloadMgr.IsReloading() {
		t.Error("Expected IsReloading to be false initially")
	}
}

func TestWatcherStartStop(t *testing.T) {
	// Create a temporary config file for testing
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("test: value"), 0644); err != nil {
		t.Fatalf("Failed to create test config: %v", err)
	}

	registry := NewRegistry()
	manager := NewManager(registry, DefaultManagerConfig(), nil)

	reloadCalled := false
	watcherCfg := WatcherConfig{
		ConfigPath:       configPath,
		DebounceInterval: 100 * time.Millisecond,
		OnReload: func(ctx context.Context) error {
			reloadCalled = true
			return nil
		},
	}

	watcher, err := NewWatcher(manager, watcherCfg)
	if err != nil {
		t.Fatalf("Failed to create watcher: %v", err)
	}

	ctx := context.Background()
	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Failed to start watcher: %v", err)
	}

	// Give watcher time to initialize
	time.Sleep(50 * time.Millisecond)

	// Modify config file to trigger reload
	if err := os.WriteFile(configPath, []byte("test: new_value"), 0644); err != nil {
		t.Fatalf("Failed to modify config: %v", err)
	}

	// Wait for debounce and reload
	time.Sleep(200 * time.Millisecond)

	if err := watcher.Stop(); err != nil {
		t.Fatalf("Failed to stop watcher: %v", err)
	}

	// Note: reloadCalled may or may not be true depending on timing
	// This is mainly testing that start/stop works without panics
	_ = reloadCalled
}

func TestHealthMonitorStartStop(t *testing.T) {
	registry := NewRegistry()
	manager := NewManager(registry, DefaultManagerConfig(), nil)

	cfg := HealthMonitorConfig{
		CheckInterval: 100 * time.Millisecond,
		MaxRetries:    1,
		RetryDelay:    50 * time.Millisecond,
	}

	monitor := NewHealthMonitor(manager, cfg)

	ctx := context.Background()
	monitor.Start(ctx)

	// Let it run briefly
	time.Sleep(150 * time.Millisecond)

	monitor.Stop()

	// Should be able to stop without blocking
}

func TestReloadManagerReload(t *testing.T) {
	registry := NewRegistry()

	// Register a mock scanner
	registry.RegisterScanner("test", func() ScannerPlugin {
		return NewMockScanner("scanner:test", 50, nil)
	})

	manager := NewManager(registry, DefaultManagerConfig(), nil)
	reloadMgr := NewReloadManager(manager)

	ctx := context.Background()

	// Load initial scanner
	if err := manager.LoadScanner(ctx, "test", nil); err != nil {
		t.Fatalf("Failed to load initial scanner: %v", err)
	}

	// Verify it's loaded
	ids := manager.LoadedScannerIDs()
	if len(ids) != 1 || ids[0] != "test" {
		t.Errorf("Expected scanner 'test' to be loaded, got %v", ids)
	}

	// Reload with scanner disabled
	scannerConfigs := map[string]map[string]any{
		"test": {"enabled": false},
	}

	if err := reloadMgr.Reload(ctx, scannerConfigs, nil); err != nil {
		t.Fatalf("Reload failed: %v", err)
	}

	// Verify scanner was unloaded
	ids = manager.LoadedScannerIDs()
	if len(ids) != 0 {
		t.Errorf("Expected no scanners after reload with disabled, got %v", ids)
	}
}
