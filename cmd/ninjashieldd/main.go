package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/brad07/ninjashield/pkg/config"
	"github.com/brad07/ninjashield/pkg/llm"
	"github.com/brad07/ninjashield/pkg/ollama"
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
	enableOllama := flag.Bool("ollama", false, "Enable Ollama-based risk scoring")
	ollamaEndpoint := flag.String("ollama-endpoint", "http://localhost:11434", "Ollama API endpoint")
	ollamaModel := flag.String("ollama-model", "gemma3", "Ollama model to use for risk assessment")
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

	// Initialize LLM engine (for LLM request evaluation)
	llmPolicy := llm.CreateLLMPolicy()
	llmEngineConfig := llm.EngineConfig{
		EnableSecrets: true,
		EnablePII:     true,
		EnableOllama:  *enableOllama,
		OllamaConfig: ollama.Config{
			Endpoint: *ollamaEndpoint,
			Model:    *ollamaModel,
			Mode:     ollama.ModeFast,
		},
	}
	llmEngine := llm.NewEngineWithConfig(llmPolicy, llmEngineConfig)
	log.Printf("LLM engine initialized (Ollama: %v)", *enableOllama)

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
