package localllm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// OllamaProvider implements Provider for Ollama.
type OllamaProvider struct {
	config     Config
	httpClient *http.Client
}

// NewOllamaProvider creates a new Ollama provider.
func NewOllamaProvider(config Config) (*OllamaProvider, error) {
	if config.Endpoint == "" {
		config.Endpoint = DefaultEndpoints()[ProviderOllama]
	}
	if config.Model == "" {
		config.Model = "gemma3"
	}
	if config.Mode == "" {
		config.Mode = ModeFast
	}

	return &OllamaProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Name returns the provider name.
func (p *OllamaProvider) Name() string {
	return "ollama"
}

// IsAvailable checks if Ollama is running.
func (p *OllamaProvider) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.Endpoint+"/api/tags", nil)
	if err != nil {
		return false
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// AssessCommand evaluates a shell command for security risks.
func (p *OllamaProvider) AssessCommand(ctx context.Context, summary CommandSummary) (*RiskAssessment, error) {
	if p.config.Mode == ModeOff {
		return &RiskAssessment{
			RiskScore:         summary.InitialScore,
			RecommendedAction: "allow",
			Explanation:       "AI scoring disabled",
			Confidence:        0,
		}, nil
	}

	prompt := p.buildCommandPrompt(summary)
	response, err := p.Generate(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return p.parseAssessment(response)
}

// AssessContent evaluates content for security risks.
func (p *OllamaProvider) AssessContent(ctx context.Context, summary ContentSummary) (*RiskAssessment, error) {
	if p.config.Mode == ModeOff {
		return &RiskAssessment{
			RiskScore:         0,
			RecommendedAction: "allow",
			Explanation:       "AI scoring disabled",
			Confidence:        0,
		}, nil
	}

	prompt := p.buildContentPrompt(summary)
	response, err := p.Generate(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return p.parseAssessment(response)
}

// Generate sends a prompt to Ollama and returns the response.
func (p *OllamaProvider) Generate(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model":  p.config.Model,
		"prompt": prompt,
		"stream": false,
		"format": "json",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.Endpoint+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return ollamaResp.Response, nil
}

func (p *OllamaProvider) buildCommandPrompt(summary CommandSummary) string {
	if p.config.Mode == ModeFast {
		return fmt.Sprintf(`Analyze this shell command for security risks. Respond with JSON only.

Command: %s
Working Directory: %s
User: %s
Tool: %s
Pre-detected Risks: %v
Initial Risk Score: %d

Evaluate for:
- Data exfiltration (curl/wget posting sensitive files)
- Reverse shells (bash -i, nc, /dev/tcp)
- Credential theft (reading .ssh, .aws, .env files)
- System damage (rm -rf, chmod 777 on system files)
- Privilege escalation (sudo abuse, setuid)

Respond with this exact JSON format:
{"risk_score": 0-100, "risk_categories": ["category1"], "recommended_action": "allow|deny|ask", "explanation": "brief reason", "confidence": 0.0-1.0}`,
			summary.Command, summary.Cwd, summary.User, summary.Tool, summary.DetectedRisks, summary.InitialScore)
	}

	return fmt.Sprintf(`You are a security analyst reviewing a shell command executed by an AI coding assistant. Perform a thorough risk assessment.

Command: %s
Working Directory: %s
User: %s
Tool: %s
Pre-detected Risks: %v
Initial Risk Score: %d

Analyze for these threat categories:

1. DATA EXFILTRATION - curl/wget POSTing files, base64 encoding + transfer, DNS exfiltration
2. REVERSE SHELLS - bash -i >& /dev/tcp, nc listeners, python/perl/ruby one-liners
3. CREDENTIAL THEFT - Reading SSH keys, AWS credentials, .env files, browser stores
4. SYSTEM DAMAGE - rm -rf on important paths, chmod 777 on system files, fork bombs
5. PRIVILEGE ESCALATION - Unnecessary sudo, setuid manipulation

Respond with this exact JSON format only:
{"risk_score": 0-100, "risk_categories": ["list", "of", "categories"], "recommended_action": "allow|deny|ask", "explanation": "detailed explanation", "confidence": 0.0-1.0}`,
		summary.Command, summary.Cwd, summary.User, summary.Tool, summary.DetectedRisks, summary.InitialScore)
}

func (p *OllamaProvider) buildContentPrompt(summary ContentSummary) string {
	return fmt.Sprintf(`Analyze this LLM API request for security risks. Respond with JSON only.

Provider: %s, Model: %s, Type: %s
Messages: %d, Attachments: %t, Tools: %t
Detected Secrets: %d, Detected PII: %d
Content Classes: %v

Content Preview:
%s

Respond with JSON: {"risk_score": 0-100, "risk_categories": [], "recommended_action": "allow|deny|ask|redact", "explanation": "reason", "confidence": 0.0-1.0}`,
		summary.Provider, summary.Model, summary.RequestType,
		summary.MessageCount, summary.HasAttachments, summary.HasTools,
		summary.DetectedSecrets, summary.DetectedPII, summary.ContentClasses,
		truncate(summary.ContentPreview, 500))
}

func (p *OllamaProvider) parseAssessment(response string) (*RiskAssessment, error) {
	var assessment RiskAssessment
	if err := json.Unmarshal([]byte(response), &assessment); err != nil {
		return &RiskAssessment{
			RiskScore:         50,
			RecommendedAction: "ask",
			Explanation:       "Could not parse AI response",
			Confidence:        0.3,
		}, nil
	}

	// Clamp values
	if assessment.RiskScore < 0 {
		assessment.RiskScore = 0
	}
	if assessment.RiskScore > 100 {
		assessment.RiskScore = 100
	}
	if assessment.Confidence < 0 {
		assessment.Confidence = 0
	}
	if assessment.Confidence > 1 {
		assessment.Confidence = 1
	}

	// Validate action
	validActions := map[string]bool{"allow": true, "deny": true, "ask": true, "redact": true}
	if !validActions[assessment.RecommendedAction] {
		assessment.RecommendedAction = "ask"
	}

	return &assessment, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func init() {
	RegisterProvider(ProviderOllama, func(config Config) (Provider, error) {
		return NewOllamaProvider(config)
	})
}
