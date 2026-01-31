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

// LMStudioProvider implements Provider for LM Studio.
// LM Studio exposes an OpenAI-compatible API.
type LMStudioProvider struct {
	config     Config
	httpClient *http.Client
}

// NewLMStudioProvider creates a new LM Studio provider.
func NewLMStudioProvider(config Config) (*LMStudioProvider, error) {
	if config.Endpoint == "" {
		config.Endpoint = DefaultEndpoints()[ProviderLMStudio]
	}
	if config.Model == "" {
		config.Model = "local-model"
	}
	if config.Mode == "" {
		config.Mode = ModeFast
	}

	return &LMStudioProvider{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// Name returns the provider name.
func (p *LMStudioProvider) Name() string {
	return "lmstudio"
}

// IsAvailable checks if LM Studio is running.
func (p *LMStudioProvider) IsAvailable(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", p.config.Endpoint+"/v1/models", nil)
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
func (p *LMStudioProvider) AssessCommand(ctx context.Context, summary CommandSummary) (*RiskAssessment, error) {
	if p.config.Mode == ModeOff {
		return &RiskAssessment{
			RiskScore:         summary.InitialScore,
			RecommendedAction: "allow",
			Explanation:       "AI scoring disabled",
			Confidence:        0,
		}, nil
	}

	prompt := buildCommandPromptOpenAI(summary, p.config.Mode)
	response, err := p.Generate(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return parseAssessmentJSON(response)
}

// AssessContent evaluates content for security risks.
func (p *LMStudioProvider) AssessContent(ctx context.Context, summary ContentSummary) (*RiskAssessment, error) {
	if p.config.Mode == ModeOff {
		return &RiskAssessment{
			RiskScore:         0,
			RecommendedAction: "allow",
			Explanation:       "AI scoring disabled",
			Confidence:        0,
		}, nil
	}

	prompt := buildContentPromptOpenAI(summary, p.config.Mode)
	response, err := p.Generate(ctx, prompt)
	if err != nil {
		return nil, err
	}

	return parseAssessmentJSON(response)
}

// Generate sends a prompt to LM Studio using OpenAI-compatible API.
func (p *LMStudioProvider) Generate(ctx context.Context, prompt string) (string, error) {
	reqBody := map[string]interface{}{
		"model": p.config.Model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a security analyst. Respond only with valid JSON."},
			{"role": "user", "content": prompt},
		},
		"temperature": 0.1,
		"max_tokens":  500,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", p.config.Endpoint+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("lmstudio returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var chatResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&chatResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("no response from LM Studio")
	}

	return chatResp.Choices[0].Message.Content, nil
}

// Shared prompt builders for OpenAI-compatible APIs

func buildCommandPromptOpenAI(summary CommandSummary, mode Mode) string {
	if mode == ModeFast {
		return fmt.Sprintf(`Analyze this shell command for security risks:

Command: %s
Working Directory: %s
User: %s
Tool: %s
Pre-detected Risks: %v

Respond with JSON only:
{"risk_score": 0-100, "risk_categories": ["category"], "recommended_action": "allow|deny|ask", "explanation": "reason", "confidence": 0.0-1.0}`,
			summary.Command, summary.Cwd, summary.User, summary.Tool, summary.DetectedRisks)
	}

	return fmt.Sprintf(`Analyze this shell command for security risks:

Command: %s
Working Directory: %s
User: %s
Tool: %s
Pre-detected Risks: %v
Initial Risk Score: %d

Check for: data exfiltration, reverse shells, credential theft, system damage, privilege escalation.

Respond with JSON only:
{"risk_score": 0-100, "risk_categories": [], "recommended_action": "allow|deny|ask", "explanation": "reason", "confidence": 0.0-1.0}`,
		summary.Command, summary.Cwd, summary.User, summary.Tool, summary.DetectedRisks, summary.InitialScore)
}

func buildContentPromptOpenAI(summary ContentSummary, mode Mode) string {
	return fmt.Sprintf(`Analyze this LLM API request for security risks:

Provider: %s, Model: %s, Messages: %d
Detected Secrets: %d, Detected PII: %d
Content Preview: %s

Respond with JSON: {"risk_score": 0-100, "risk_categories": [], "recommended_action": "allow|deny|ask|redact", "explanation": "reason", "confidence": 0.0-1.0}`,
		summary.Provider, summary.Model, summary.MessageCount,
		summary.DetectedSecrets, summary.DetectedPII, truncate(summary.ContentPreview, 300))
}

func parseAssessmentJSON(response string) (*RiskAssessment, error) {
	var assessment RiskAssessment
	if err := json.Unmarshal([]byte(response), &assessment); err != nil {
		return &RiskAssessment{
			RiskScore:         50,
			RecommendedAction: "ask",
			Explanation:       "Could not parse AI response",
			Confidence:        0.3,
		}, nil
	}

	// Clamp and validate
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

	validActions := map[string]bool{"allow": true, "deny": true, "ask": true, "redact": true}
	if !validActions[assessment.RecommendedAction] {
		assessment.RecommendedAction = "ask"
	}

	return &assessment, nil
}

func init() {
	RegisterProvider(ProviderLMStudio, func(config Config) (Provider, error) {
		return NewLMStudioProvider(config)
	})
}
