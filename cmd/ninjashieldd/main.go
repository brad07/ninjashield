package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/brad07/ninjashield/pkg/config"
	"github.com/brad07/ninjashield/pkg/llm"
	"github.com/brad07/ninjashield/pkg/localllm"
	_ "github.com/brad07/ninjashield/pkg/localllm" // Register providers
	"github.com/brad07/ninjashield/pkg/plugin"
	_ "github.com/brad07/ninjashield/plugins" // Register all plugins
	"github.com/brad07/ninjashield/pkg/policy"
	"github.com/brad07/ninjashield/pkg/policy/packs"
	"github.com/brad07/ninjashield/pkg/server"
	"github.com/brad07/ninjashield/pkg/storage"
)

const version = "0.1.0"

func main() {
	// Parse command line flags
	host := flag.String("host", "localhost", "Host to bind to")
	port := flag.Int("port", 7575, "Port to listen on")
	packName := flag.String("pack", "balanced", "Policy pack to use (conservative, balanced, developer-friendly)")
	configPath := flag.String("config", "", "Path to configuration file")

	// Local LLM provider flags
	llmProvider := flag.String("llm", "", "Local LLM provider (ollama, lmstudio) - enables AI-based command scoring")
	llmEndpoint := flag.String("llm-endpoint", "", "LLM API endpoint (auto-detected if not specified)")
	llmModel := flag.String("llm-model", "", "LLM model to use (provider default if not specified)")
	llmMode := flag.String("llm-mode", "fast", "LLM scoring mode (fast, strict)")

	// Plugin flags
	usePluginSystem := flag.Bool("plugins", false, "Use new plugin system for scanners and LLM providers")

	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("ninjashieldd v%s\n", version)
		os.Exit(0)
	}

	fmt.Printf("NinjaShield Daemon v%s\n", version)

	// Load configuration
	var cfg *config.Config
	var err error
	if *configPath != "" {
		cfg, err = config.LoadFrom(*configPath, ".")
		if err != nil {
			log.Fatalf("Failed to load configuration: %v", err)
		}
	} else {
		cfg, err = config.Load(".")
		if err != nil {
			// Use default configuration if no config file found
			cfg = config.DefaultConfig()
		}
	}

	// Override config with command line flags
	if *host != "localhost" {
		cfg.Server.Host = *host
	}
	if *port != 7575 {
		cfg.Server.Port = *port
	}
	if *packName != "balanced" {
		cfg.Policy.ActivePack = *packName
	}

	// Load policy pack
	pol, err := packs.LoadByName(cfg.Policy.ActivePack)
	if err != nil {
		log.Fatalf("Failed to load policy pack %q: %v", cfg.Policy.ActivePack, err)
	}
	log.Printf("Loaded policy pack: %s (%d rules)", pol.ID, len(pol.Rules))

	// Initialize policy engine (for command evaluation)
	engine := policy.NewEngine(pol)

	// Initialize plugin manager if using plugin system
	var pluginManager *plugin.Manager
	if *usePluginSystem {
		pluginManager = initializePluginManager(cfg, *llmProvider, *llmEndpoint, *llmModel, *llmMode)
		log.Printf("Plugin system enabled")
	}

	// Initialize local LLM provider if configured (legacy path)
	var localProvider localllm.Provider
	if !*usePluginSystem && *llmProvider != "" {
		localProvider = initializeLegacyLLMProvider(*llmProvider, *llmEndpoint, *llmModel, *llmMode, engine)
	}

	// Initialize LLM engine (for LLM request evaluation)
	llmPolicy := llm.CreateLLMPolicy()
	llmEngineConfig := llm.EngineConfig{
		EnableSecrets: true,
		EnablePII:     true,
		EnableLLM:     localProvider != nil || (pluginManager != nil && pluginManager.IsLLMAvailable(context.Background())),
		LLMProvider:   localProvider,
	}
	llmEngine := llm.NewEngineWithConfig(llmPolicy, llmEngineConfig)
	log.Printf("LLM engine initialized (AI scoring: %v)", llmEngineConfig.EnableLLM)

	// Initialize storage
	store := storage.NewMemoryStore()

	// Create server configuration
	serverConfig := server.Config{
		Host:            cfg.Server.Host,
		Port:            cfg.Server.Port,
		ReadTimeout:     server.DefaultConfig().ReadTimeout,
		WriteTimeout:    server.DefaultConfig().WriteTimeout,
		ShutdownTimeout: server.DefaultConfig().ShutdownTimeout,
	}

	// Create and start server
	srv := server.New(serverConfig, engine, store)
	srv.SetLLMEngine(llmEngine)
	if pluginManager != nil {
		srv.SetPluginManager(pluginManager)
	}
	if err := srv.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("Daemon running on http://%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Println("Press Ctrl+C to stop")

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("Received signal %v, shutting down...", sig)

	if err := srv.Stop(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	// Shutdown plugin manager
	if pluginManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := pluginManager.Shutdown(ctx); err != nil {
			log.Printf("Error shutting down plugin manager: %v", err)
		}
		cancel()
	}

	if err := store.Close(); err != nil {
		log.Printf("Error closing storage: %v", err)
	}

	log.Println("Daemon stopped")
}

// initializePluginManager creates and configures the plugin manager.
func initializePluginManager(cfg *config.Config, llmProvider, llmEndpoint, llmModel, llmMode string) *plugin.Manager {
	ctx := context.Background()

	// Create manager with default configuration
	managerConfig := plugin.DefaultManagerConfig()
	managerConfig.ParallelScan = cfg.Pipeline.ParallelScanners
	managerConfig.FailOpen = cfg.Pipeline.FailOpen
	if cfg.Pipeline.ScannerTimeoutSec > 0 {
		managerConfig.ScannerTimeout = time.Duration(cfg.Pipeline.ScannerTimeoutSec) * time.Second
	}
	if cfg.Pipeline.LLMTimeoutSec > 0 {
		managerConfig.LLMTimeout = time.Duration(cfg.Pipeline.LLMTimeoutSec) * time.Second
	}

	manager := plugin.NewManager(nil, managerConfig, nil)

	// Load scanner plugins from configuration
	for name, scannerCfg := range cfg.Plugins.Scanners {
		if !scannerCfg.Enabled {
			continue
		}

		pluginConfig := make(map[string]any)
		pluginConfig["enabled"] = scannerCfg.Enabled
		pluginConfig["priority"] = scannerCfg.Priority
		for k, v := range scannerCfg.Config {
			pluginConfig[k] = v
		}

		if err := manager.LoadScanner(ctx, name, pluginConfig); err != nil {
			log.Printf("Warning: Failed to load scanner plugin %q: %v", name, err)
		}
	}

	log.Printf("Loaded %d scanner plugins: %v", len(manager.LoadedScannerIDs()), manager.LoadedScannerIDs())

	// Load LLM provider from command line or configuration
	if llmProvider != "" {
		// Command line takes precedence
		providerConfig := map[string]any{
			"enabled": true,
		}
		if llmEndpoint != "" {
			providerConfig["endpoint"] = llmEndpoint
		}
		if llmModel != "" {
			providerConfig["model"] = llmModel
		}
		if llmMode != "" {
			providerConfig["mode"] = llmMode
		}

		if err := manager.LoadLLMProvider(ctx, llmProvider, providerConfig); err != nil {
			log.Printf("Warning: Failed to load LLM provider plugin %q: %v", llmProvider, err)
		} else {
			if err := manager.SetActiveLLMProvider(llmProvider); err != nil {
				log.Printf("Warning: Failed to set active LLM provider: %v", err)
			} else {
				log.Printf("Loaded LLM provider plugin: %s", llmProvider)
			}
		}
	} else {
		// Load from configuration
		for name, providerCfg := range cfg.Plugins.LLMProviders {
			if !providerCfg.Enabled {
				continue
			}

			pluginConfig := map[string]any{
				"enabled":  providerCfg.Enabled,
				"endpoint": providerCfg.Endpoint,
				"model":    providerCfg.Model,
				"mode":     providerCfg.Mode,
			}
			if providerCfg.APIKey != "" {
				pluginConfig["api_key"] = providerCfg.APIKey
			}

			if err := manager.LoadLLMProvider(ctx, name, pluginConfig); err != nil {
				log.Printf("Warning: Failed to load LLM provider plugin %q: %v", name, err)
				continue
			}

			// Set the first available provider as active
			if manager.IsLLMAvailable(ctx) {
				if err := manager.SetActiveLLMProvider(name); err == nil {
					log.Printf("Loaded LLM provider plugin: %s", name)
					break
				}
			}
		}
	}

	return manager
}

// initializeLegacyLLMProvider initializes the LLM provider using the legacy system.
func initializeLegacyLLMProvider(provider, endpoint, model, mode string, engine *policy.Engine) localllm.Provider {
	providerType := localllm.ProviderType(provider)
	providerConfig := localllm.DefaultConfig(providerType)

	if endpoint != "" {
		providerConfig.Endpoint = endpoint
	}
	if model != "" {
		providerConfig.Model = model
	}
	if mode == "strict" {
		providerConfig.Mode = localllm.ModeStrict
	} else {
		providerConfig.Mode = localllm.ModeFast
	}

	localProvider, err := localllm.NewProvider(providerConfig)
	if err != nil {
		log.Printf("Warning: Failed to create LLM provider %q: %v", provider, err)
		return nil
	}

	// Check if provider is available
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if localProvider.IsAvailable(ctx) {
		log.Printf("Local LLM provider: %s (model: %s, mode: %s)", localProvider.Name(), providerConfig.Model, providerConfig.Mode)
		// Set on policy engine for command scoring
		engine.SetLLMProvider(localProvider)
		return localProvider
	}

	log.Printf("Warning: LLM provider %q not available at %s", provider, providerConfig.Endpoint)
	return nil
}
