// Package config handles NinjaShield configuration loading and management.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	// DefaultConfigDir is the default configuration directory name.
	DefaultConfigDir = ".ninjashield"
	// DefaultConfigFile is the default configuration file name.
	DefaultConfigFile = "config.yaml"
	// ProjectPolicyFile is the project-level policy override file name.
	ProjectPolicyFile = "policy.yaml"
)

// Config holds the NinjaShield configuration.
type Config struct {
	// Server settings
	Server ServerConfig `yaml:"server"`

	// Policy settings
	Policy PolicyConfig `yaml:"policy"`

	// Scanner settings
	Scanners ScannersConfig `yaml:"scanners"`

	// Logging settings
	Logging LoggingConfig `yaml:"logging"`

	// Local LLM settings (optional)
	LLM LLMConfig `yaml:"llm"`
}

// ServerConfig holds HTTP server settings.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// PolicyConfig holds policy engine settings.
type PolicyConfig struct {
	ActivePack  string `yaml:"active_pack"`
	ProjectPath string `yaml:"project_path"` // Path where project override was loaded from
}

// ScannersConfig holds scanner toggle settings.
type ScannersConfig struct {
	Secrets  bool `yaml:"secrets"`
	PII      bool `yaml:"pii"`
	Commands bool `yaml:"commands"`
}

// LoggingConfig holds logging settings.
type LoggingConfig struct {
	Path          string `yaml:"path"`
	EncryptionKey string `yaml:"encryption_key,omitempty"`
	MaxSizeMB     int    `yaml:"max_size_mb"`
	MaxAgeDays    int    `yaml:"max_age_days"`
}

// LLMConfig holds optional local LLM integration settings.
type LLMConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"` // "ollama", "lmstudio", etc.
	Endpoint string `yaml:"endpoint"`
	Model    string `yaml:"model"`
	Mode     string `yaml:"mode"` // "fast" or "strict"
}

// DefaultConfig returns the default configuration.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host: "localhost",
			Port: 7575,
		},
		Policy: PolicyConfig{
			ActivePack: "balanced",
		},
		Scanners: ScannersConfig{
			Secrets:  true,
			PII:      true,
			Commands: true,
		},
		Logging: LoggingConfig{
			Path:       filepath.Join("~", DefaultConfigDir, "audit.db"),
			MaxSizeMB:  100,
			MaxAgeDays: 90,
		},
		LLM: LLMConfig{
			Enabled:  false,
			Provider: "ollama",
			Endpoint: "http://localhost:11434",
			Model:    "gemma3",
			Mode:     "fast",
		},
	}
}

// Load loads the configuration from the default location (~/.ninjashield/config.yaml).
// If the config file doesn't exist, it returns the default configuration.
// If projectDir is provided, it also looks for project-level overrides.
func Load(projectDir string) (*Config, error) {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return nil, fmt.Errorf("failed to determine config path: %w", err)
	}

	return LoadFrom(configPath, projectDir)
}

// LoadFrom loads configuration from a specific path with optional project overrides.
func LoadFrom(configPath, projectDir string) (*Config, error) {
	cfg := DefaultConfig()

	// Expand the config path
	expandedPath, err := ExpandPath(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to expand config path: %w", err)
	}

	// Load main config if it exists
	if _, err := os.Stat(expandedPath); err == nil {
		data, err := os.ReadFile(expandedPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}

		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Load project-level overrides if projectDir is provided
	if projectDir != "" {
		if err := loadProjectOverrides(cfg, projectDir); err != nil {
			return nil, fmt.Errorf("failed to load project overrides: %w", err)
		}
	}

	// Expand paths in the config
	if err := cfg.expandPaths(); err != nil {
		return nil, fmt.Errorf("failed to expand paths in config: %w", err)
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// loadProjectOverrides loads and merges project-level policy overrides.
func loadProjectOverrides(cfg *Config, projectDir string) error {
	projectConfigPath := filepath.Join(projectDir, DefaultConfigDir, ProjectPolicyFile)

	if _, err := os.Stat(projectConfigPath); os.IsNotExist(err) {
		return nil // No project overrides, that's fine
	}

	data, err := os.ReadFile(projectConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read project config: %w", err)
	}

	// ProjectOverride only allows overriding certain fields
	var override ProjectOverride
	if err := yaml.Unmarshal(data, &override); err != nil {
		return fmt.Errorf("failed to parse project config: %w", err)
	}

	// Apply overrides
	if override.Policy.ActivePack != "" {
		cfg.Policy.ActivePack = override.Policy.ActivePack
	}
	cfg.Policy.ProjectPath = projectConfigPath

	// Merge scanner settings if specified
	if override.Scanners != nil {
		if override.Scanners.Secrets != nil {
			cfg.Scanners.Secrets = *override.Scanners.Secrets
		}
		if override.Scanners.PII != nil {
			cfg.Scanners.PII = *override.Scanners.PII
		}
		if override.Scanners.Commands != nil {
			cfg.Scanners.Commands = *override.Scanners.Commands
		}
	}

	return nil
}

// ProjectOverride represents the allowed project-level configuration overrides.
type ProjectOverride struct {
	Policy struct {
		ActivePack string `yaml:"active_pack"`
	} `yaml:"policy"`
	Scanners *struct {
		Secrets  *bool `yaml:"secrets"`
		PII      *bool `yaml:"pii"`
		Commands *bool `yaml:"commands"`
	} `yaml:"scanners"`
}

// expandPaths expands ~ and environment variables in path fields.
func (c *Config) expandPaths() error {
	var err error
	c.Logging.Path, err = ExpandPath(c.Logging.Path)
	if err != nil {
		return fmt.Errorf("failed to expand logging path: %w", err)
	}
	return nil
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	var errs []string

	// Validate server config
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Sprintf("invalid server port: %d (must be 1-65535)", c.Server.Port))
	}

	// Validate policy config
	validPacks := map[string]bool{
		"conservative":      true,
		"balanced":          true,
		"developer-friendly": true,
	}
	if !validPacks[c.Policy.ActivePack] {
		errs = append(errs, fmt.Sprintf("invalid policy pack: %s (must be conservative, balanced, or developer-friendly)", c.Policy.ActivePack))
	}

	// Validate logging config
	if c.Logging.MaxSizeMB < 1 {
		errs = append(errs, "logging max_size_mb must be at least 1")
	}
	if c.Logging.MaxAgeDays < 1 {
		errs = append(errs, "logging max_age_days must be at least 1")
	}

	// Validate LLM config if enabled
	if c.LLM.Enabled {
		validProviders := map[string]bool{
			"ollama":   true,
			"lmstudio": true,
			"localai":  true,
		}
		if !validProviders[c.LLM.Provider] {
			errs = append(errs, fmt.Sprintf("invalid llm provider: %s (must be ollama, lmstudio, or localai)", c.LLM.Provider))
		}
		if c.LLM.Endpoint == "" {
			errs = append(errs, "llm endpoint is required when enabled")
		}
		if c.LLM.Model == "" {
			errs = append(errs, "llm model is required when enabled")
		}
		if c.LLM.Mode != "fast" && c.LLM.Mode != "strict" {
			errs = append(errs, fmt.Sprintf("invalid llm mode: %s (must be fast or strict)", c.LLM.Mode))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// DefaultConfigPath returns the default configuration file path.
func DefaultConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, DefaultConfigDir, DefaultConfigFile), nil
}

// DefaultConfigDir returns the default configuration directory path.
func DefaultConfigDirPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, DefaultConfigDir), nil
}

// ExpandPath expands ~ to the user's home directory and environment variables.
func ExpandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(homeDir, path[2:])
	} else if path == "~" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = homeDir
	}

	return os.ExpandEnv(path), nil
}

// Initialize creates the default configuration directory and file if they don't exist.
// Returns the path to the config file and whether it was newly created.
func Initialize() (string, bool, error) {
	configDir, err := DefaultConfigDirPath()
	if err != nil {
		return "", false, fmt.Errorf("failed to determine config directory: %w", err)
	}

	configPath := filepath.Join(configDir, DefaultConfigFile)

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		return configPath, false, nil
	}

	// Create config directory
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return "", false, fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write default config
	cfg := DefaultConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal default config: %w", err)
	}

	// Add header comment
	header := []byte(`# NinjaShield Configuration
# Documentation: https://github.com/brad07/ninjashield

`)
	data = append(header, data...)

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return "", false, fmt.Errorf("failed to write config file: %w", err)
	}

	return configPath, true, nil
}

// Save writes the configuration to the default location.
func (c *Config) Save() error {
	configPath, err := DefaultConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}

	return c.SaveTo(configPath)
}

// SaveTo writes the configuration to a specific path.
func (c *Config) SaveTo(path string) error {
	expandedPath, err := ExpandPath(path)
	if err != nil {
		return fmt.Errorf("failed to expand path: %w", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(expandedPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	header := []byte(`# NinjaShield Configuration
# Documentation: https://github.com/brad07/ninjashield

`)
	data = append(header, data...)

	if err := os.WriteFile(expandedPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Address returns the server listen address.
func (c *Config) Address() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}
