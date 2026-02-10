// Package plugins provides a single import point for all built-in NinjaShield plugins.
// Importing this package registers all compile-time plugins with the global registry.
package plugins

import (
	// Import all scanner plugins to trigger their init() registration
	_ "github.com/brad07/ninjashield/plugins/scanners/commands"
	_ "github.com/brad07/ninjashield/plugins/scanners/pii"
	_ "github.com/brad07/ninjashield/plugins/scanners/secrets"

	// Import all LLM provider plugins to trigger their init() registration
	_ "github.com/brad07/ninjashield/plugins/llm/lmstudio"
	_ "github.com/brad07/ninjashield/plugins/llm/ollama"

	// Import all integration plugins to trigger their init() registration
	_ "github.com/brad07/ninjashield/plugins/integrations/claudecode"
)

// RegisterAll is a no-op function that can be called to ensure plugins are registered.
// The actual registration happens in the init() functions of each plugin package.
func RegisterAll() {
	// This function exists to provide an explicit registration point.
	// Plugins are registered by their init() functions when imported above.
}
