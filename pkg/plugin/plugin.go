// Package plugin provides the core plugin framework for NinjaShield.
// It defines base interfaces and types that all plugins must implement.
package plugin

import (
	"context"
	"errors"
	"time"
)

// Common errors.
var (
	// ErrProviderUnavailable is returned when an LLM provider is not accessible.
	ErrProviderUnavailable = errors.New("provider is unavailable")

	// ErrPluginNotFound is returned when a plugin is not registered.
	ErrPluginNotFound = errors.New("plugin not found")

	// ErrPluginNotInitialized is returned when a plugin hasn't been initialized.
	ErrPluginNotInitialized = errors.New("plugin not initialized")
)

// PluginError represents an error from the plugin system.
type PluginError struct {
	Op       string // Operation that failed
	PluginID string // Plugin involved, if any
	Err      string // Error message
}

func (e *PluginError) Error() string {
	if e.PluginID != "" {
		return e.Op + " " + e.PluginID + ": " + e.Err
	}
	return e.Op + ": " + e.Err
}

// PluginType represents the category of a plugin.
type PluginType string

const (
	PluginTypeScanner     PluginType = "scanner"
	PluginTypeLLMProvider PluginType = "llm_provider"
	PluginTypeIntegration PluginType = "integration"
	PluginTypePreProcess  PluginType = "pre_process"
	PluginTypePostProcess PluginType = "post_process"
)

// PluginStatus represents the current state of a plugin.
type PluginStatus string

const (
	PluginStatusUninitialized PluginStatus = "uninitialized"
	PluginStatusInitializing  PluginStatus = "initializing"
	PluginStatusReady         PluginStatus = "ready"
	PluginStatusError         PluginStatus = "error"
	PluginStatusShuttingDown  PluginStatus = "shutting_down"
	PluginStatusStopped       PluginStatus = "stopped"
)

// PluginTier represents the execution model of a plugin.
type PluginTier string

const (
	// TierCompileTime plugins are compiled into the binary and use Go interfaces.
	TierCompileTime PluginTier = "compile_time"
	// TierHTTP plugins communicate via HTTP/gRPC for hot-reload support.
	TierHTTP PluginTier = "http"
	// TierRPC plugins use Hashicorp go-plugin for trusted plugin isolation.
	TierRPC PluginTier = "rpc"
)

// PluginInfo contains metadata about a plugin.
type PluginInfo struct {
	// ID is the unique identifier for the plugin (e.g., "scanner:secrets", "llm:ollama").
	ID string `json:"id"`

	// Name is the human-readable name of the plugin.
	Name string `json:"name"`

	// Version is the semantic version of the plugin.
	Version string `json:"version"`

	// Type is the category of the plugin.
	Type PluginType `json:"type"`

	// Tier is the execution model of the plugin.
	Tier PluginTier `json:"tier"`

	// Description provides a brief explanation of the plugin's purpose.
	Description string `json:"description,omitempty"`

	// Author is the plugin author or maintainer.
	Author string `json:"author,omitempty"`

	// Homepage is the URL for the plugin's documentation or repository.
	Homepage string `json:"homepage,omitempty"`

	// Capabilities lists the specific features this plugin provides.
	Capabilities []string `json:"capabilities,omitempty"`

	// Dependencies lists other plugin IDs this plugin depends on.
	Dependencies []string `json:"dependencies,omitempty"`
}

// PluginState contains runtime state information about a plugin.
type PluginState struct {
	// Info contains the plugin metadata.
	Info PluginInfo `json:"info"`

	// Status is the current state of the plugin.
	Status PluginStatus `json:"status"`

	// LastHealthCheck is the timestamp of the last successful health check.
	LastHealthCheck time.Time `json:"last_health_check,omitempty"`

	// LastError contains the most recent error message, if any.
	LastError string `json:"last_error,omitempty"`

	// LoadedAt is when the plugin was initialized.
	LoadedAt time.Time `json:"loaded_at,omitempty"`

	// Stats contains runtime statistics.
	Stats PluginStats `json:"stats"`
}

// PluginStats contains runtime statistics for a plugin.
type PluginStats struct {
	// TotalCalls is the total number of times the plugin has been invoked.
	TotalCalls int64 `json:"total_calls"`

	// SuccessfulCalls is the number of successful invocations.
	SuccessfulCalls int64 `json:"successful_calls"`

	// FailedCalls is the number of failed invocations.
	FailedCalls int64 `json:"failed_calls"`

	// TotalLatencyMs is the cumulative latency in milliseconds.
	TotalLatencyMs int64 `json:"total_latency_ms"`

	// AverageLatencyMs is the average latency per call.
	AverageLatencyMs float64 `json:"average_latency_ms"`
}

// Plugin is the base interface that all plugins must implement.
type Plugin interface {
	// Info returns metadata about the plugin.
	Info() PluginInfo

	// Init initializes the plugin with the given configuration.
	// This is called once when the plugin is loaded.
	Init(ctx context.Context, config map[string]any) error

	// Shutdown gracefully stops the plugin.
	// This is called when the plugin manager is shutting down or reloading.
	Shutdown(ctx context.Context) error

	// HealthCheck verifies the plugin is functioning correctly.
	// Returns nil if healthy, an error otherwise.
	HealthCheck(ctx context.Context) error
}

// PluginConfig represents the configuration for a plugin.
type PluginConfig struct {
	// ID is the plugin identifier.
	ID string `yaml:"id" json:"id"`

	// Enabled determines if the plugin should be loaded.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Type specifies the plugin type (for type-specific loading).
	Type PluginType `yaml:"type" json:"type"`

	// Tier specifies the execution model.
	Tier PluginTier `yaml:"tier" json:"tier"`

	// Priority determines the order of execution (higher = earlier).
	Priority int `yaml:"priority" json:"priority"`

	// Config contains plugin-specific configuration.
	Config map[string]any `yaml:"config" json:"config"`

	// URL is the endpoint for HTTP/gRPC plugins.
	URL string `yaml:"url,omitempty" json:"url,omitempty"`

	// Path is the filesystem path for RPC plugins.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// Timeout is the maximum time to wait for plugin responses.
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// RetryCount is the number of retries on failure.
	RetryCount int `yaml:"retry_count" json:"retry_count"`

	// RetryDelay is the delay between retries.
	RetryDelay time.Duration `yaml:"retry_delay" json:"retry_delay"`
}

// DefaultPluginConfig returns a PluginConfig with sensible defaults.
func DefaultPluginConfig(id string, pluginType PluginType) PluginConfig {
	return PluginConfig{
		ID:         id,
		Enabled:    true,
		Type:       pluginType,
		Tier:       TierCompileTime,
		Priority:   50,
		Config:     make(map[string]any),
		Timeout:    5 * time.Second,
		RetryCount: 0,
		RetryDelay: 100 * time.Millisecond,
	}
}
