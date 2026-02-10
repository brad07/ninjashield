// Package plugin provides the plugin system for NinjaShield.
package plugin

import (
	"context"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatcherConfig holds configuration for the config watcher.
type WatcherConfig struct {
	// ConfigPath is the path to watch for changes.
	ConfigPath string

	// DebounceInterval is the time to wait before triggering reload after changes.
	DebounceInterval time.Duration

	// OnReload is called when configuration changes are detected.
	OnReload func(ctx context.Context) error

	// OnError is called when an error occurs during watching or reloading.
	OnError func(err error)
}

// DefaultWatcherConfig returns a WatcherConfig with sensible defaults.
func DefaultWatcherConfig() WatcherConfig {
	return WatcherConfig{
		DebounceInterval: 500 * time.Millisecond,
		OnError:          func(err error) { log.Printf("Watcher error: %v", err) },
	}
}

// Watcher monitors configuration files and triggers plugin reloads.
type Watcher struct {
	config   WatcherConfig
	watcher  *fsnotify.Watcher
	manager  *Manager
	stopCh   chan struct{}
	doneCh   chan struct{}
	mu       sync.Mutex
	running  bool
}

// NewWatcher creates a new configuration watcher.
func NewWatcher(manager *Manager, config WatcherConfig) (*Watcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Watcher{
		config:  config,
		watcher: fsWatcher,
		manager: manager,
		stopCh:  make(chan struct{}),
		doneCh:  make(chan struct{}),
	}, nil
}

// Start begins watching for configuration changes.
func (w *Watcher) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	// Add the config file's directory to the watch list
	configDir := filepath.Dir(w.config.ConfigPath)
	if err := w.watcher.Add(configDir); err != nil {
		return err
	}

	go w.watchLoop(ctx)
	return nil
}

// Stop stops the watcher.
func (w *Watcher) Stop() error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopCh)
	<-w.doneCh
	return w.watcher.Close()
}

// watchLoop is the main event loop for the watcher.
func (w *Watcher) watchLoop(ctx context.Context) {
	defer close(w.doneCh)

	var debounceTimer *time.Timer
	var debounceCh <-chan time.Time

	configFile := filepath.Base(w.config.ConfigPath)

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case <-w.stopCh:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			// Only react to the specific config file
			if filepath.Base(event.Name) != configFile {
				continue
			}

			// React to write and create events
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				// Debounce: reset timer on each event
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.NewTimer(w.config.DebounceInterval)
				debounceCh = debounceTimer.C
			}

		case <-debounceCh:
			// Debounce timer fired, trigger reload
			log.Printf("Configuration change detected, reloading plugins...")
			if w.config.OnReload != nil {
				if err := w.config.OnReload(ctx); err != nil {
					if w.config.OnError != nil {
						w.config.OnError(err)
					}
				} else {
					log.Printf("Plugin reload completed successfully")
				}
			}
			debounceCh = nil

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			if w.config.OnError != nil {
				w.config.OnError(err)
			}
		}
	}
}

// HealthMonitor monitors plugin health and handles recovery.
type HealthMonitor struct {
	manager       *Manager
	checkInterval time.Duration
	maxRetries    int
	retryDelay    time.Duration
	onUnhealthy   func(pluginID string, err error)
	onRecovered   func(pluginID string)
	stopCh        chan struct{}
	doneCh        chan struct{}
	mu            sync.Mutex
	running       bool
}

// HealthMonitorConfig holds configuration for health monitoring.
type HealthMonitorConfig struct {
	// CheckInterval is how often to check plugin health.
	CheckInterval time.Duration

	// MaxRetries is the maximum number of recovery attempts.
	MaxRetries int

	// RetryDelay is the time between recovery attempts.
	RetryDelay time.Duration

	// OnUnhealthy is called when a plugin becomes unhealthy.
	OnUnhealthy func(pluginID string, err error)

	// OnRecovered is called when a plugin recovers.
	OnRecovered func(pluginID string)
}

// DefaultHealthMonitorConfig returns a HealthMonitorConfig with sensible defaults.
func DefaultHealthMonitorConfig() HealthMonitorConfig {
	return HealthMonitorConfig{
		CheckInterval: 30 * time.Second,
		MaxRetries:    3,
		RetryDelay:    5 * time.Second,
		OnUnhealthy:   func(id string, err error) { log.Printf("Plugin %s unhealthy: %v", id, err) },
		OnRecovered:   func(id string) { log.Printf("Plugin %s recovered", id) },
	}
}

// NewHealthMonitor creates a new health monitor.
func NewHealthMonitor(manager *Manager, config HealthMonitorConfig) *HealthMonitor {
	return &HealthMonitor{
		manager:       manager,
		checkInterval: config.CheckInterval,
		maxRetries:    config.MaxRetries,
		retryDelay:    config.RetryDelay,
		onUnhealthy:   config.OnUnhealthy,
		onRecovered:   config.OnRecovered,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

// Start begins health monitoring.
func (h *HealthMonitor) Start(ctx context.Context) {
	h.mu.Lock()
	if h.running {
		h.mu.Unlock()
		return
	}
	h.running = true
	h.mu.Unlock()

	go h.monitorLoop(ctx)
}

// Stop stops the health monitor.
func (h *HealthMonitor) Stop() {
	h.mu.Lock()
	if !h.running {
		h.mu.Unlock()
		return
	}
	h.running = false
	h.mu.Unlock()

	close(h.stopCh)
	<-h.doneCh
}

// monitorLoop is the main health check loop.
func (h *HealthMonitor) monitorLoop(ctx context.Context) {
	defer close(h.doneCh)

	ticker := time.NewTicker(h.checkInterval)
	defer ticker.Stop()

	// Track unhealthy plugins and retry counts
	unhealthy := make(map[string]int)

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.stopCh:
			return
		case <-ticker.C:
			h.checkAllPlugins(ctx, unhealthy)
		}
	}
}

// checkAllPlugins checks health of all loaded plugins.
func (h *HealthMonitor) checkAllPlugins(ctx context.Context, unhealthy map[string]int) {
	// Check scanners
	for _, id := range h.manager.LoadedScannerIDs() {
		h.checkPlugin(ctx, id, unhealthy)
	}

	// Check LLM providers
	for _, id := range h.manager.LoadedLLMProviderIDs() {
		h.checkPlugin(ctx, id, unhealthy)
	}
}

// checkPlugin checks a single plugin's health.
func (h *HealthMonitor) checkPlugin(ctx context.Context, pluginID string, unhealthy map[string]int) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := h.manager.HealthCheckPlugin(checkCtx, pluginID)
	if err != nil {
		retries := unhealthy[pluginID]
		if retries == 0 {
			// First failure
			if h.onUnhealthy != nil {
				h.onUnhealthy(pluginID, err)
			}
		}

		unhealthy[pluginID] = retries + 1

		// Attempt recovery if under max retries
		if retries < h.maxRetries {
			go h.attemptRecovery(ctx, pluginID, unhealthy)
		}
	} else {
		// Plugin is healthy
		if _, wasUnhealthy := unhealthy[pluginID]; wasUnhealthy {
			delete(unhealthy, pluginID)
			if h.onRecovered != nil {
				h.onRecovered(pluginID)
			}
		}
	}
}

// attemptRecovery tries to recover an unhealthy plugin.
func (h *HealthMonitor) attemptRecovery(ctx context.Context, pluginID string, unhealthy map[string]int) {
	time.Sleep(h.retryDelay)

	// Try to reinitialize the plugin
	// This is a simplified recovery - in practice you might want to
	// unload and reload the plugin with its original config
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := h.manager.HealthCheckPlugin(checkCtx, pluginID)
	if err == nil {
		delete(unhealthy, pluginID)
		if h.onRecovered != nil {
			h.onRecovered(pluginID)
		}
	}
}

// ReloadManager handles graceful plugin reloading.
type ReloadManager struct {
	manager    *Manager
	mu         sync.RWMutex
	reloading  bool
}

// NewReloadManager creates a new reload manager.
func NewReloadManager(manager *Manager) *ReloadManager {
	return &ReloadManager{
		manager: manager,
	}
}

// Reload performs a graceful reload of plugins based on new configuration.
func (r *ReloadManager) Reload(ctx context.Context, scannerConfigs map[string]map[string]any, llmConfigs map[string]map[string]any) error {
	r.mu.Lock()
	if r.reloading {
		r.mu.Unlock()
		return ErrReloadInProgress
	}
	r.reloading = true
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.reloading = false
		r.mu.Unlock()
	}()

	// Get current plugin IDs
	currentScanners := make(map[string]bool)
	for _, id := range r.manager.LoadedScannerIDs() {
		currentScanners[id] = true
	}

	currentLLMs := make(map[string]bool)
	for _, id := range r.manager.LoadedLLMProviderIDs() {
		currentLLMs[id] = true
	}

	// Load new scanners and update existing ones
	for name, config := range scannerConfigs {
		enabled, _ := config["enabled"].(bool)
		if !enabled {
			// Unload disabled scanners
			if currentScanners[name] {
				if err := r.manager.UnloadScanner(ctx, name); err != nil {
					log.Printf("Warning: failed to unload scanner %s: %v", name, err)
				}
			}
			continue
		}

		if currentScanners[name] {
			// Scanner already loaded, could implement config update here
			delete(currentScanners, name)
		} else {
			// Load new scanner
			if err := r.manager.LoadScanner(ctx, name, config); err != nil {
				log.Printf("Warning: failed to load scanner %s: %v", name, err)
			}
		}
	}

	// Unload scanners that are no longer in config
	for name := range currentScanners {
		if err := r.manager.UnloadScanner(ctx, name); err != nil {
			log.Printf("Warning: failed to unload scanner %s: %v", name, err)
		}
	}

	// Load new LLM providers and update existing ones
	for name, config := range llmConfigs {
		enabled, _ := config["enabled"].(bool)
		if !enabled {
			if currentLLMs[name] {
				if err := r.manager.UnloadLLMProvider(ctx, name); err != nil {
					log.Printf("Warning: failed to unload LLM provider %s: %v", name, err)
				}
			}
			continue
		}

		if currentLLMs[name] {
			delete(currentLLMs, name)
		} else {
			if err := r.manager.LoadLLMProvider(ctx, name, config); err != nil {
				log.Printf("Warning: failed to load LLM provider %s: %v", name, err)
			}
		}
	}

	// Unload LLM providers no longer in config
	for name := range currentLLMs {
		if err := r.manager.UnloadLLMProvider(ctx, name); err != nil {
			log.Printf("Warning: failed to unload LLM provider %s: %v", name, err)
		}
	}

	return nil
}

// IsReloading returns whether a reload is in progress.
func (r *ReloadManager) IsReloading() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.reloading
}

// ErrReloadInProgress is returned when a reload is already in progress.
var ErrReloadInProgress = &PluginError{Op: "reload", Err: "reload already in progress"}
