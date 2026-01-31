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

	// Initialize local LLM provider if configured
	var localProvider localllm.Provider
	if *llmProvider != "" {
		providerType := localllm.ProviderType(*llmProvider)
		providerConfig := localllm.DefaultConfig(providerType)

		if *llmEndpoint != "" {
			providerConfig.Endpoint = *llmEndpoint
		}
		if *llmModel != "" {
			providerConfig.Model = *llmModel
		}
		if *llmMode == "strict" {
			providerConfig.Mode = localllm.ModeStrict
		} else {
			providerConfig.Mode = localllm.ModeFast
		}

		var err error
		localProvider, err = localllm.NewProvider(providerConfig)
		if err != nil {
			log.Printf("Warning: Failed to create LLM provider %q: %v", *llmProvider, err)
		} else {
			// Check if provider is available
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if localProvider.IsAvailable(ctx) {
				log.Printf("Local LLM provider: %s (model: %s, mode: %s)", localProvider.Name(), providerConfig.Model, providerConfig.Mode)
				// Set on policy engine for command scoring
				engine.SetLLMProvider(localProvider)
			} else {
				log.Printf("Warning: LLM provider %q not available at %s", *llmProvider, providerConfig.Endpoint)
				localProvider = nil
			}
			cancel()
		}
	}

	// Initialize LLM engine (for LLM request evaluation)
	llmPolicy := llm.CreateLLMPolicy()
	llmEngineConfig := llm.EngineConfig{
		EnableSecrets: true,
		EnablePII:     true,
		EnableLLM:     localProvider != nil,
		LLMProvider:   localProvider,
	}
	llmEngine := llm.NewEngineWithConfig(llmPolicy, llmEngineConfig)
	log.Printf("LLM engine initialized (AI scoring: %v)", localProvider != nil)

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

	if err := store.Close(); err != nil {
		log.Printf("Error closing storage: %v", err)
	}

	log.Println("Daemon stopped")
}
