package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Host != "localhost" {
		t.Errorf("expected host localhost, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 7575 {
		t.Errorf("expected port 7575, got %d", cfg.Server.Port)
	}
	if cfg.Policy.ActivePack != "balanced" {
		t.Errorf("expected active_pack balanced, got %s", cfg.Policy.ActivePack)
	}
	if !cfg.Scanners.Secrets {
		t.Error("expected secrets scanner enabled by default")
	}
	if !cfg.Scanners.PII {
		t.Error("expected PII scanner enabled by default")
	}
	if !cfg.Scanners.Commands {
		t.Error("expected commands scanner enabled by default")
	}
	if cfg.LLM.Enabled {
		t.Error("expected LLM disabled by default")
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid default config",
			modify:  func(c *Config) {},
			wantErr: false,
		},
		{
			name: "invalid port - too low",
			modify: func(c *Config) {
				c.Server.Port = 0
			},
			wantErr: true,
		},
		{
			name: "invalid port - too high",
			modify: func(c *Config) {
				c.Server.Port = 70000
			},
			wantErr: true,
		},
		{
			name: "invalid policy pack",
			modify: func(c *Config) {
				c.Policy.ActivePack = "nonexistent"
			},
			wantErr: true,
		},
		{
			name: "valid conservative pack",
			modify: func(c *Config) {
				c.Policy.ActivePack = "conservative"
			},
			wantErr: false,
		},
		{
			name: "valid developer-friendly pack",
			modify: func(c *Config) {
				c.Policy.ActivePack = "developer-friendly"
			},
			wantErr: false,
		},
		{
			name: "invalid logging max size",
			modify: func(c *Config) {
				c.Logging.MaxSizeMB = 0
			},
			wantErr: true,
		},
		{
			name: "invalid logging max age",
			modify: func(c *Config) {
				c.Logging.MaxAgeDays = 0
			},
			wantErr: true,
		},
		{
			name: "llm enabled without endpoint",
			modify: func(c *Config) {
				c.LLM.Enabled = true
				c.LLM.Endpoint = ""
			},
			wantErr: true,
		},
		{
			name: "llm enabled without model",
			modify: func(c *Config) {
				c.LLM.Enabled = true
				c.LLM.Model = ""
			},
			wantErr: true,
		},
		{
			name: "llm invalid mode",
			modify: func(c *Config) {
				c.LLM.Enabled = true
				c.LLM.Mode = "invalid"
			},
			wantErr: true,
		},
		{
			name: "llm valid strict mode",
			modify: func(c *Config) {
				c.LLM.Enabled = true
				c.LLM.Mode = "strict"
			},
			wantErr: false,
		},
		{
			name: "llm invalid provider",
			modify: func(c *Config) {
				c.LLM.Enabled = true
				c.LLM.Provider = "invalid"
			},
			wantErr: true,
		},
		{
			name: "llm valid lmstudio provider",
			modify: func(c *Config) {
				c.LLM.Enabled = true
				c.LLM.Provider = "lmstudio"
				c.LLM.Endpoint = "http://localhost:1234"
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpandPath(t *testing.T) {
	homeDir, _ := os.UserHomeDir()

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name: "expand tilde prefix",
			path: "~/test/path",
			want: filepath.Join(homeDir, "test/path"),
		},
		{
			name: "expand tilde only",
			path: "~",
			want: homeDir,
		},
		{
			name: "no expansion needed",
			path: "/absolute/path",
			want: "/absolute/path",
		},
		{
			name: "relative path unchanged",
			path: "relative/path",
			want: "relative/path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExpandPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "ninjashield-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Write a test config file
	configContent := `server:
  host: "0.0.0.0"
  port: 8080
policy:
  active_pack: "conservative"
scanners:
  secrets: false
  pii: true
  commands: true
logging:
  path: "/var/log/ninjashield/audit.db"
  max_size_mb: 50
  max_age_days: 30
llm:
  enabled: false
  provider: "ollama"
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFrom(configPath, "")
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("expected host 0.0.0.0, got %s", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Server.Port)
	}
	if cfg.Policy.ActivePack != "conservative" {
		t.Errorf("expected active_pack conservative, got %s", cfg.Policy.ActivePack)
	}
	if cfg.Scanners.Secrets {
		t.Error("expected secrets scanner disabled")
	}
	if cfg.Logging.MaxSizeMB != 50 {
		t.Errorf("expected max_size_mb 50, got %d", cfg.Logging.MaxSizeMB)
	}
}

func TestLoadWithProjectOverrides(t *testing.T) {
	// Create temp directory for test
	tmpDir, err := os.MkdirTemp("", "ninjashield-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Write main config file
	configContent := `server:
  host: "localhost"
  port: 7575
policy:
  active_pack: "balanced"
scanners:
  secrets: true
  pii: true
  commands: true
logging:
  path: "/tmp/audit.db"
  max_size_mb: 100
  max_age_days: 90
`
	configPath := filepath.Join(tmpDir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Create project directory with override
	projectDir := filepath.Join(tmpDir, "myproject")
	projectConfigDir := filepath.Join(projectDir, ".ninjashield")
	if err := os.MkdirAll(projectConfigDir, 0700); err != nil {
		t.Fatal(err)
	}

	projectOverride := `policy:
  active_pack: "developer-friendly"
scanners:
  pii: false
`
	projectConfigPath := filepath.Join(projectConfigDir, "policy.yaml")
	if err := os.WriteFile(projectConfigPath, []byte(projectOverride), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFrom(configPath, projectDir)
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	// Check that project override was applied
	if cfg.Policy.ActivePack != "developer-friendly" {
		t.Errorf("expected active_pack developer-friendly, got %s", cfg.Policy.ActivePack)
	}
	if cfg.Scanners.PII {
		t.Error("expected PII scanner disabled by project override")
	}
	// Check that non-overridden values remain
	if !cfg.Scanners.Secrets {
		t.Error("expected secrets scanner still enabled")
	}
	if cfg.Policy.ProjectPath != projectConfigPath {
		t.Errorf("expected project path %s, got %s", projectConfigPath, cfg.Policy.ProjectPath)
	}
}

func TestConfigAddress(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Address() != "localhost:7575" {
		t.Errorf("expected localhost:7575, got %s", cfg.Address())
	}

	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = 8080
	if cfg.Address() != "0.0.0.0:8080" {
		t.Errorf("expected 0.0.0.0:8080, got %s", cfg.Address())
	}
}

func TestInitializeAndSave(t *testing.T) {
	// Create temp directory to use as home
	tmpDir, err := os.MkdirTemp("", "ninjashield-home-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Test SaveTo
	configPath := filepath.Join(tmpDir, ".ninjashield", "config.yaml")
	cfg := DefaultConfig()
	cfg.Server.Port = 9999

	if err := cfg.SaveTo(configPath); err != nil {
		t.Fatalf("SaveTo() error = %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config file was not created")
	}

	// Load it back
	loaded, err := LoadFrom(configPath, "")
	if err != nil {
		t.Fatalf("LoadFrom() error = %v", err)
	}

	if loaded.Server.Port != 9999 {
		t.Errorf("expected port 9999, got %d", loaded.Server.Port)
	}
}

func TestLoadNonexistentFile(t *testing.T) {
	// Loading from nonexistent file should return defaults
	cfg, err := LoadFrom("/nonexistent/path/config.yaml", "")
	if err != nil {
		t.Fatalf("LoadFrom() should not error for nonexistent file, got: %v", err)
	}

	// Should have default values
	if cfg.Server.Port != 7575 {
		t.Errorf("expected default port 7575, got %d", cfg.Server.Port)
	}
}
