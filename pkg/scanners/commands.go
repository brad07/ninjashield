package scanners

import (
	"regexp"
	"strings"
)

// CommandScanner detects dangerous command patterns.
type CommandScanner struct {
	patterns []commandPattern
}

type commandPattern struct {
	name        string
	category    string
	regex       *regexp.Regexp
	severity    string
	confidence  float64
	message     string
	riskFactors []string
}

// NewCommandScanner creates a new command scanner.
func NewCommandScanner() *CommandScanner {
	return &CommandScanner{
		patterns: defaultCommandPatterns(),
	}
}

func defaultCommandPatterns() []commandPattern {
	return []commandPattern{
		// ================================================================
		// REMOTE CODE EXECUTION
		// ================================================================
		{
			name:        "pipe_to_shell",
			category:    "remote_code_execution",
			regex:       regexp.MustCompile(`(curl|wget|fetch|http|https)[^|]*\|\s*(sh|bash|zsh|ksh|fish|dash)`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Remote code execution: piping download to shell",
			riskFactors: []string{"network", "code_execution", "untrusted_source"},
		},
		{
			name:        "pipe_to_shell_path",
			category:    "remote_code_execution",
			regex:       regexp.MustCompile(`(curl|wget|fetch)[^|]*\|\s*/bin/(sh|bash)|/usr/bin/(sh|bash)`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Remote code execution: piping download to shell (absolute path)",
			riskFactors: []string{"network", "code_execution", "untrusted_source"},
		},
		{
			name:        "eval_curl",
			category:    "remote_code_execution",
			regex:       regexp.MustCompile(`eval\s*["\']?\$\((curl|wget|fetch)[^)]*\)`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Remote code execution: eval with downloaded content",
			riskFactors: []string{"network", "code_execution", "eval"},
		},
		{
			name:        "source_url",
			category:    "remote_code_execution",
			regex:       regexp.MustCompile(`(source|\.) <\((curl|wget|fetch)[^)]*\)`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Remote code execution: sourcing downloaded content",
			riskFactors: []string{"network", "code_execution"},
		},
		{
			name:        "python_exec_url",
			category:    "remote_code_execution",
			regex:       regexp.MustCompile(`python[23]?\s+-c\s+['"]import\s+urllib`),
			severity:    "high",
			confidence:  0.80,
			message:     "Potential remote code execution via Python",
			riskFactors: []string{"network", "code_execution"},
		},

		// ================================================================
		// DESTRUCTIVE FILE OPERATIONS
		// ================================================================
		{
			name:        "rm_rf_root",
			category:    "destructive",
			regex:       regexp.MustCompile(`rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[^/]*\s+/\s*$`),
			severity:    "critical",
			confidence:  0.99,
			message:     "Catastrophic: recursive force delete of root filesystem",
			riskFactors: []string{"destructive", "system_wide"},
		},
		{
			name:        "rm_rf_home",
			category:    "destructive",
			regex:       regexp.MustCompile(`rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[^~]*\s+(~|\$HOME)/?$`),
			severity:    "critical",
			confidence:  0.99,
			message:     "Catastrophic: recursive force delete of home directory",
			riskFactors: []string{"destructive", "user_data"},
		},
		{
			name:        "rm_rf_system",
			category:    "destructive",
			regex:       regexp.MustCompile(`rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)[^/]*\s+/(usr|bin|sbin|etc|var|boot|lib|lib64|opt|root|sys|proc)/?`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Catastrophic: recursive force delete of system directory",
			riskFactors: []string{"destructive", "system_wide"},
		},
		{
			name:        "rm_recursive",
			category:    "destructive",
			regex:       regexp.MustCompile(`rm\s+(-[a-zA-Z]*r|-R|--recursive)`),
			severity:    "medium",
			confidence:  0.80,
			message:     "Recursive file deletion",
			riskFactors: []string{"destructive"},
		},
		{
			name:        "find_delete",
			category:    "destructive",
			regex:       regexp.MustCompile(`find\s+.*\s+-delete`),
			severity:    "high",
			confidence:  0.85,
			message:     "Bulk file deletion via find",
			riskFactors: []string{"destructive", "bulk_operation"},
		},
		{
			name:        "find_exec_rm",
			category:    "destructive",
			regex:       regexp.MustCompile(`find\s+.*\s+-exec\s+rm`),
			severity:    "high",
			confidence:  0.85,
			message:     "Bulk file deletion via find -exec rm",
			riskFactors: []string{"destructive", "bulk_operation"},
		},
		{
			name:        "shred",
			category:    "destructive",
			regex:       regexp.MustCompile(`shred\s+`),
			severity:    "high",
			confidence:  0.90,
			message:     "Secure file deletion (unrecoverable)",
			riskFactors: []string{"destructive", "unrecoverable"},
		},

		// ================================================================
		// DISK/DEVICE OPERATIONS
		// ================================================================
		{
			name:        "dd_device_write",
			category:    "destructive",
			regex:       regexp.MustCompile(`dd\s+.*of=/dev/(sd[a-z]|hd[a-z]|nvme[0-9]|disk[0-9]|vd[a-z])`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Direct disk write via dd",
			riskFactors: []string{"destructive", "disk_operation"},
		},
		{
			name:        "dd_zero",
			category:    "destructive",
			regex:       regexp.MustCompile(`dd\s+.*if=/dev/(zero|urandom)`),
			severity:    "high",
			confidence:  0.80,
			message:     "Disk overwrite pattern detected",
			riskFactors: []string{"destructive"},
		},
		{
			name:        "mkfs",
			category:    "destructive",
			regex:       regexp.MustCompile(`mkfs(\.[a-z0-9]+)?\s+`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Filesystem format command",
			riskFactors: []string{"destructive", "disk_operation"},
		},
		{
			name:        "fdisk",
			category:    "destructive",
			regex:       regexp.MustCompile(`(fdisk|parted|gdisk)\s+/dev/`),
			severity:    "critical",
			confidence:  0.90,
			message:     "Disk partitioning command",
			riskFactors: []string{"destructive", "disk_operation"},
		},

		// ================================================================
		// PRIVILEGE ESCALATION
		// ================================================================
		{
			name:        "sudo",
			category:    "privileged",
			regex:       regexp.MustCompile(`sudo\s+`),
			severity:    "medium",
			confidence:  0.95,
			message:     "Privilege escalation via sudo",
			riskFactors: []string{"privileged"},
		},
		{
			name:        "su_root",
			category:    "privileged",
			regex:       regexp.MustCompile(`su\s+(-|root)`),
			severity:    "high",
			confidence:  0.90,
			message:     "Switch to root user",
			riskFactors: []string{"privileged"},
		},
		{
			name:        "chmod_777",
			category:    "privileged",
			regex:       regexp.MustCompile(`chmod\s+777\s+`),
			severity:    "high",
			confidence:  0.95,
			message:     "Overly permissive file permissions",
			riskFactors: []string{"security", "permissions"},
		},
		{
			name:        "chmod_suid",
			category:    "privileged",
			regex:       regexp.MustCompile(`chmod\s+[u+]?[0-7]*s`),
			severity:    "critical",
			confidence:  0.85,
			message:     "Setting SUID/SGID bit",
			riskFactors: []string{"privileged", "security"},
		},
		{
			name:        "chown_root",
			category:    "privileged",
			regex:       regexp.MustCompile(`chown\s+(root|0):`),
			severity:    "high",
			confidence:  0.80,
			message:     "Changing file ownership to root",
			riskFactors: []string{"privileged"},
		},

		// ================================================================
		// NETWORK OPERATIONS
		// ================================================================
		{
			name:        "nc_listen",
			category:    "network",
			regex:       regexp.MustCompile(`(nc|netcat|ncat)\s+(-[a-zA-Z]*l|-l)`),
			severity:    "high",
			confidence:  0.80,
			message:     "Netcat listener (potential backdoor)",
			riskFactors: []string{"network", "backdoor"},
		},
		{
			name:        "reverse_shell",
			category:    "network",
			regex:       regexp.MustCompile(`(bash|sh|zsh)\s+-i\s+[>&]+\s+/dev/tcp/`),
			severity:    "critical",
			confidence:  0.95,
			message:     "Reverse shell pattern detected",
			riskFactors: []string{"network", "backdoor", "code_execution"},
		},
		{
			name:        "ssh_keyscan",
			category:    "network",
			regex:       regexp.MustCompile(`ssh-keyscan\s+`),
			severity:    "medium",
			confidence:  0.70,
			message:     "SSH key scanning",
			riskFactors: []string{"network", "reconnaissance"},
		},
		{
			name:        "curl_upload",
			category:    "network",
			regex:       regexp.MustCompile(`curl\s+.*(-F|--form|-d|--data|-T|--upload-file)`),
			severity:    "medium",
			confidence:  0.70,
			message:     "Data upload via curl",
			riskFactors: []string{"network", "data_exfiltration"},
		},

		// ================================================================
		// SENSITIVE FILE ACCESS
		// ================================================================
		{
			name:        "read_shadow",
			category:    "sensitive_access",
			regex:       regexp.MustCompile(`(cat|less|more|head|tail|vim?|nano|grep)\s+[^\n]*(/etc/shadow|/etc/passwd)`),
			severity:    "high",
			confidence:  0.85,
			message:     "Accessing system authentication files",
			riskFactors: []string{"sensitive", "credentials"},
		},
		{
			name:        "read_ssh_keys",
			category:    "sensitive_access",
			regex:       regexp.MustCompile(`(cat|less|more|head|tail)\s+[^\n]*\.ssh/(id_|.*_key)`),
			severity:    "critical",
			confidence:  0.90,
			message:     "Accessing SSH private keys",
			riskFactors: []string{"sensitive", "credentials"},
		},
		{
			name:        "read_env",
			category:    "sensitive_access",
			regex:       regexp.MustCompile(`(cat|less|more|head|tail|grep|source|\.)\s+[^\n]*\.env`),
			severity:    "high",
			confidence:  0.80,
			message:     "Accessing environment file (may contain secrets)",
			riskFactors: []string{"sensitive", "credentials"},
		},
		{
			name:        "read_history",
			category:    "sensitive_access",
			regex:       regexp.MustCompile(`(cat|less|more|head|tail)\s+[^\n]*\.(bash_history|zsh_history|history)`),
			severity:    "medium",
			confidence:  0.75,
			message:     "Accessing command history",
			riskFactors: []string{"sensitive"},
		},

		// ================================================================
		// PACKAGE INSTALLATION
		// ================================================================
		{
			name:        "npm_install_global",
			category:    "install",
			regex:       regexp.MustCompile(`npm\s+(i|install)\s+(-g|--global)`),
			severity:    "medium",
			confidence:  0.85,
			message:     "Global npm package installation",
			riskFactors: []string{"install", "global"},
		},
		{
			name:        "pip_install",
			category:    "install",
			regex:       regexp.MustCompile(`pip3?\s+install\s+`),
			severity:    "low",
			confidence:  0.80,
			message:     "Python package installation",
			riskFactors: []string{"install"},
		},
		{
			name:        "apt_install",
			category:    "install",
			regex:       regexp.MustCompile(`(apt|apt-get)\s+(install|upgrade)\s+`),
			severity:    "medium",
			confidence:  0.85,
			message:     "System package installation",
			riskFactors: []string{"install", "system"},
		},
		{
			name:        "brew_install",
			category:    "install",
			regex:       regexp.MustCompile(`brew\s+(install|upgrade)\s+`),
			severity:    "low",
			confidence:  0.80,
			message:     "Homebrew package installation",
			riskFactors: []string{"install"},
		},

		// ================================================================
		// SYSTEM MODIFICATION
		// ================================================================
		{
			name:        "crontab_edit",
			category:    "system",
			regex:       regexp.MustCompile(`crontab\s+(-e|-r|-l)`),
			severity:    "medium",
			confidence:  0.85,
			message:     "Crontab modification",
			riskFactors: []string{"system", "persistence"},
		},
		{
			name:        "systemctl_modify",
			category:    "system",
			regex:       regexp.MustCompile(`systemctl\s+(enable|disable|start|stop|restart|mask)\s+`),
			severity:    "medium",
			confidence:  0.80,
			message:     "System service modification",
			riskFactors: []string{"system"},
		},
		{
			name:        "iptables",
			category:    "system",
			regex:       regexp.MustCompile(`iptables\s+`),
			severity:    "high",
			confidence:  0.85,
			message:     "Firewall rule modification",
			riskFactors: []string{"system", "network"},
		},

		// ================================================================
		// OBFUSCATION
		// ================================================================
		{
			name:        "base64_decode_exec",
			category:    "obfuscation",
			regex:       regexp.MustCompile(`base64\s+(-d|--decode)[^|]*\|\s*(sh|bash|python|perl|ruby)`),
			severity:    "critical",
			confidence:  0.90,
			message:     "Executing base64-decoded content",
			riskFactors: []string{"obfuscation", "code_execution"},
		},
		{
			name:        "hex_decode_exec",
			category:    "obfuscation",
			regex:       regexp.MustCompile(`xxd\s+(-r|--revert)[^|]*\|\s*(sh|bash)`),
			severity:    "critical",
			confidence:  0.90,
			message:     "Executing hex-decoded content",
			riskFactors: []string{"obfuscation", "code_execution"},
		},
		{
			name:        "eval_var",
			category:    "obfuscation",
			regex:       regexp.MustCompile(`eval\s+["\']?\$`),
			severity:    "high",
			confidence:  0.75,
			message:     "Eval with variable (potential code injection)",
			riskFactors: []string{"obfuscation", "code_execution"},
		},

		// ================================================================
		// FORK BOMB / DoS
		// ================================================================
		{
			name:        "fork_bomb",
			category:    "dos",
			regex:       regexp.MustCompile(`:\(\)\{\s*:\|:&\s*\};:`),
			severity:    "critical",
			confidence:  0.99,
			message:     "Fork bomb detected",
			riskFactors: []string{"dos", "system_crash"},
		},
		{
			name:        "while_true_fork",
			category:    "dos",
			regex:       regexp.MustCompile(`while\s+true\s*;\s*do\s+.*&\s*done`),
			severity:    "high",
			confidence:  0.70,
			message:     "Potential fork bomb pattern",
			riskFactors: []string{"dos"},
		},
	}
}

// Name returns the scanner name.
func (s *CommandScanner) Name() string {
	return "commands"
}

// Scan analyzes the input for dangerous command patterns.
func (s *CommandScanner) Scan(input string) []Finding {
	var findings []Finding

	for _, pattern := range s.patterns {
		matches := pattern.regex.FindAllStringIndex(input, -1)
		for _, match := range matches {
			findings = append(findings, Finding{
				Type:       pattern.name,
				Category:   pattern.category,
				Severity:   pattern.severity,
				Confidence: pattern.confidence,
				Message:    pattern.message,
				Location: &Location{
					Start: match[0],
					End:   match[1],
				},
			})
		}
	}

	return findings
}

// CommandRiskInfo provides detailed risk information about a command.
type CommandRiskInfo struct {
	Command       string   `json:"command"`
	Executable    string   `json:"executable"`
	RiskLevel     string   `json:"risk_level"`
	RiskScore     int      `json:"risk_score"`
	Categories    []string `json:"categories"`
	Findings      []Finding `json:"findings"`
	Flags         []string `json:"flags"`
	HasPipe       bool     `json:"has_pipe"`
	HasRedirect   bool     `json:"has_redirect"`
	HasBackground bool     `json:"has_background"`
}

// AnalyzeCommand provides detailed risk analysis of a command.
func (s *CommandScanner) AnalyzeCommand(cmd string) *CommandRiskInfo {
	info := &CommandRiskInfo{
		Command:    cmd,
		Categories: []string{},
		Findings:   s.Scan(cmd),
	}

	// Parse basic command structure
	parts := strings.Fields(cmd)
	if len(parts) > 0 {
		info.Executable = parts[0]
	}

	// Extract flags
	for _, part := range parts {
		if strings.HasPrefix(part, "-") {
			info.Flags = append(info.Flags, part)
		}
	}

	// Check for shell operators
	info.HasPipe = strings.Contains(cmd, "|")
	info.HasRedirect = strings.ContainsAny(cmd, "<>")
	info.HasBackground = strings.HasSuffix(strings.TrimSpace(cmd), "&")

	// Calculate risk level and score
	maxSeverity := "low"
	severityOrder := map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

	categorySet := make(map[string]bool)
	for _, f := range info.Findings {
		if severityOrder[f.Severity] > severityOrder[maxSeverity] {
			maxSeverity = f.Severity
		}
		if !categorySet[f.Category] {
			categorySet[f.Category] = true
			info.Categories = append(info.Categories, f.Category)
		}
	}

	info.RiskLevel = maxSeverity
	switch maxSeverity {
	case "critical":
		info.RiskScore = 100
	case "high":
		info.RiskScore = 75
	case "medium":
		info.RiskScore = 50
	case "low":
		info.RiskScore = 25
	default:
		info.RiskScore = 0
	}

	return info
}
