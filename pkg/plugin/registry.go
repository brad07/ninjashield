package plugin

import (
	"fmt"
	"sync"
)

var (
	// Global registry instance
	globalRegistry = NewRegistry()
)

// Registry manages plugin factories for creating plugin instances.
type Registry struct {
	mu sync.RWMutex

	// Scanner factories indexed by plugin ID.
	scannerFactories map[string]ScannerFactory

	// LLM provider factories indexed by plugin ID.
	llmProviderFactories map[string]LLMProviderFactory

	// Integration factories indexed by plugin ID.
	integrationFactories map[string]IntegrationFactory
}

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		scannerFactories:     make(map[string]ScannerFactory),
		llmProviderFactories: make(map[string]LLMProviderFactory),
		integrationFactories: make(map[string]IntegrationFactory),
	}
}

// RegisterScanner registers a scanner factory with the given ID.
func (r *Registry) RegisterScanner(id string, factory ScannerFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.scannerFactories[id]; exists {
		return fmt.Errorf("scanner already registered: %s", id)
	}

	r.scannerFactories[id] = factory
	return nil
}

// RegisterLLMProvider registers an LLM provider factory with the given ID.
func (r *Registry) RegisterLLMProvider(id string, factory LLMProviderFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.llmProviderFactories[id]; exists {
		return fmt.Errorf("LLM provider already registered: %s", id)
	}

	r.llmProviderFactories[id] = factory
	return nil
}

// CreateScanner creates a new scanner instance using the registered factory.
func (r *Registry) CreateScanner(id string) (ScannerPlugin, error) {
	r.mu.RLock()
	factory, exists := r.scannerFactories[id]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("scanner not registered: %s", id)
	}

	return factory(), nil
}

// CreateLLMProvider creates a new LLM provider instance using the registered factory.
func (r *Registry) CreateLLMProvider(id string) (LLMProviderPlugin, error) {
	r.mu.RLock()
	factory, exists := r.llmProviderFactories[id]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("LLM provider not registered: %s", id)
	}

	return factory(), nil
}

// ListScanners returns all registered scanner IDs.
func (r *Registry) ListScanners() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.scannerFactories))
	for id := range r.scannerFactories {
		ids = append(ids, id)
	}
	return ids
}

// ListLLMProviders returns all registered LLM provider IDs.
func (r *Registry) ListLLMProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.llmProviderFactories))
	for id := range r.llmProviderFactories {
		ids = append(ids, id)
	}
	return ids
}

// HasScanner checks if a scanner is registered.
func (r *Registry) HasScanner(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.scannerFactories[id]
	return exists
}

// HasLLMProvider checks if an LLM provider is registered.
func (r *Registry) HasLLMProvider(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.llmProviderFactories[id]
	return exists
}

// UnregisterScanner removes a scanner factory.
func (r *Registry) UnregisterScanner(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.scannerFactories, id)
}

// UnregisterLLMProvider removes an LLM provider factory.
func (r *Registry) UnregisterLLMProvider(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.llmProviderFactories, id)
}

// RegisterIntegration registers an integration factory with the given ID.
func (r *Registry) RegisterIntegration(id string, factory IntegrationFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.integrationFactories[id]; exists {
		return fmt.Errorf("integration already registered: %s", id)
	}

	r.integrationFactories[id] = factory
	return nil
}

// CreateIntegration creates a new integration instance using the registered factory.
func (r *Registry) CreateIntegration(id string) (IntegrationPlugin, error) {
	r.mu.RLock()
	factory, exists := r.integrationFactories[id]
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("integration not registered: %s", id)
	}

	return factory(), nil
}

// ListIntegrations returns all registered integration IDs.
func (r *Registry) ListIntegrations() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.integrationFactories))
	for id := range r.integrationFactories {
		ids = append(ids, id)
	}
	return ids
}

// HasIntegration checks if an integration is registered.
func (r *Registry) HasIntegration(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.integrationFactories[id]
	return exists
}

// UnregisterIntegration removes an integration factory.
func (r *Registry) UnregisterIntegration(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.integrationFactories, id)
}

// Global registry functions for convenience

// RegisterScanner registers a scanner factory with the global registry.
func RegisterScanner(id string, factory ScannerFactory) error {
	return globalRegistry.RegisterScanner(id, factory)
}

// RegisterLLMProvider registers an LLM provider factory with the global registry.
func RegisterLLMProvider(id string, factory LLMProviderFactory) error {
	return globalRegistry.RegisterLLMProvider(id, factory)
}

// CreateScanner creates a scanner using the global registry.
func CreateScanner(id string) (ScannerPlugin, error) {
	return globalRegistry.CreateScanner(id)
}

// CreateLLMProvider creates an LLM provider using the global registry.
func CreateLLMProvider(id string) (LLMProviderPlugin, error) {
	return globalRegistry.CreateLLMProvider(id)
}

// ListRegisteredScanners returns all registered scanner IDs from the global registry.
func ListRegisteredScanners() []string {
	return globalRegistry.ListScanners()
}

// ListRegisteredLLMProviders returns all registered LLM provider IDs from the global registry.
func ListRegisteredLLMProviders() []string {
	return globalRegistry.ListLLMProviders()
}

// RegisterIntegration registers an integration factory with the global registry.
func RegisterIntegration(id string, factory IntegrationFactory) error {
	return globalRegistry.RegisterIntegration(id, factory)
}

// CreateIntegration creates an integration using the global registry.
func CreateIntegration(id string) (IntegrationPlugin, error) {
	return globalRegistry.CreateIntegration(id)
}

// ListRegisteredIntegrations returns all registered integration IDs from the global registry.
func ListRegisteredIntegrations() []string {
	return globalRegistry.ListIntegrations()
}

// GlobalRegistry returns the global registry instance.
func GlobalRegistry() *Registry {
	return globalRegistry
}
