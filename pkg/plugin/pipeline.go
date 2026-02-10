package plugin

import (
	"context"
	"fmt"
	"time"

	"github.com/brad07/ninjashield/pkg/policy"
	"github.com/brad07/ninjashield/pkg/scanners"
)

// PipelineConfig configures the evaluation pipeline.
type PipelineConfig struct {
	// ParallelScanners enables parallel scanner execution.
	ParallelScanners bool `yaml:"parallel_scanners" json:"parallel_scanners"`

	// ScannerTimeout is the maximum time for scanner execution.
	ScannerTimeout time.Duration `yaml:"scanner_timeout" json:"scanner_timeout"`

	// LLMTimeout is the maximum time for LLM assessment.
	LLMTimeout time.Duration `yaml:"llm_timeout" json:"llm_timeout"`

	// FailOpen determines behavior when plugins fail.
	FailOpen bool `yaml:"fail_open" json:"fail_open"`

	// DefaultRiskTolerance is the default risk tolerance level.
	DefaultRiskTolerance RiskTolerance `yaml:"default_risk_tolerance" json:"default_risk_tolerance"`

	// CustomThresholds allows overriding the default thresholds for each tolerance level.
	CustomThresholds map[RiskTolerance]RiskThresholds `yaml:"custom_thresholds,omitempty" json:"custom_thresholds,omitempty"`

	// AIScoring configures AI scoring behavior.
	AIScoring AIScoringConfig `yaml:"ai_scoring" json:"ai_scoring"`
}

// AIScoringConfig configures AI scoring behavior.
type AIScoringConfig struct {
	// Enabled determines if AI scoring is active.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// UpgradeOnly means AI can escalate but not downgrade risk.
	UpgradeOnly bool `yaml:"upgrade_only" json:"upgrade_only"`

	// MinConfidence is the minimum confidence for AI to influence decisions.
	MinConfidence float64 `yaml:"min_confidence" json:"min_confidence"`

	// TriggerConditions define when AI scoring should run.
	TriggerConditions []AITriggerCondition `yaml:"trigger_conditions" json:"trigger_conditions"`
}

// AITriggerCondition defines when AI scoring should be invoked.
type AITriggerCondition struct {
	// Type is the condition type.
	Type AITriggerType `yaml:"type" json:"type"`

	// Value is the threshold value for comparison conditions.
	Value int `yaml:"value,omitempty" json:"value,omitempty"`

	// Decision is the decision value for decision conditions.
	Decision policy.Decision `yaml:"decision,omitempty" json:"decision,omitempty"`
}

// AITriggerType defines types of AI trigger conditions.
type AITriggerType string

const (
	AITriggerRiskScoreGTE    AITriggerType = "risk_score_gte"
	AITriggerRiskScoreLTE    AITriggerType = "risk_score_lte"
	AITriggerDecisionEquals  AITriggerType = "decision_equals"
	AITriggerAlways          AITriggerType = "always"
	AITriggerHasFindings     AITriggerType = "has_findings"
	AITriggerContentClass    AITriggerType = "content_class"
)

// RiskTolerance represents how tolerant the system is to risky operations.
// Lower tolerance = more restrictive (deny more), higher tolerance = more permissive.
type RiskTolerance string

const (
	// RiskToleranceStrict denies at lower risk scores, asks for confirmation more often.
	// Use for production environments or sensitive operations.
	RiskToleranceStrict RiskTolerance = "strict"

	// RiskToleranceBalanced provides moderate thresholds suitable for most use cases.
	RiskToleranceBalanced RiskTolerance = "balanced"

	// RiskTolerancePermissive allows more operations through, only denying high-risk ones.
	// Use for development environments or trusted contexts.
	RiskTolerancePermissive RiskTolerance = "permissive"
)

// RiskThresholds defines the score thresholds for each decision level.
type RiskThresholds struct {
	// DenyThreshold: scores >= this result in DENY
	DenyThreshold int `yaml:"deny_threshold" json:"deny_threshold"`

	// AskThreshold: scores >= this (but < DenyThreshold) result in ASK
	AskThreshold int `yaml:"ask_threshold" json:"ask_threshold"`

	// SeverityDeny: severity levels that always result in DENY
	SeverityDeny []string `yaml:"severity_deny" json:"severity_deny"`

	// SeverityAsk: severity levels that result in ASK (if not already denied)
	SeverityAsk []string `yaml:"severity_ask" json:"severity_ask"`
}

// DefaultThresholds returns the thresholds for a given risk tolerance level.
func DefaultThresholds(tolerance RiskTolerance) RiskThresholds {
	switch tolerance {
	case RiskToleranceStrict:
		return RiskThresholds{
			DenyThreshold: 50,
			AskThreshold:  25,
			SeverityDeny:  []string{"critical", "high"},
			SeverityAsk:   []string{"medium"},
		}
	case RiskTolerancePermissive:
		return RiskThresholds{
			DenyThreshold: 90,
			AskThreshold:  75,
			SeverityDeny:  []string{"critical"},
			SeverityAsk:   []string{"high"},
		}
	default: // Balanced
		return RiskThresholds{
			DenyThreshold: 75,
			AskThreshold:  50,
			SeverityDeny:  []string{"critical"},
			SeverityAsk:   []string{"high"},
		}
	}
}

// DefaultPipelineConfig returns a PipelineConfig with sensible defaults.
func DefaultPipelineConfig() PipelineConfig {
	return PipelineConfig{
		ParallelScanners:     true,
		ScannerTimeout:       5 * time.Second,
		LLMTimeout:           30 * time.Second,
		FailOpen:             false,
		DefaultRiskTolerance: RiskToleranceBalanced,
		AIScoring: AIScoringConfig{
			Enabled:       true,
			UpgradeOnly:   true,
			MinConfidence: 0.7,
			TriggerConditions: []AITriggerCondition{
				{Type: AITriggerRiskScoreGTE, Value: 50},
				{Type: AITriggerDecisionEquals, Decision: policy.DecisionAsk},
			},
		},
	}
}

// Pipeline orchestrates the evaluation of content through multiple stages.
type Pipeline struct {
	manager *Manager
	config  PipelineConfig
}

// NewPipeline creates a new evaluation pipeline.
func NewPipeline(manager *Manager, config PipelineConfig) *Pipeline {
	return &Pipeline{
		manager: manager,
		config:  config,
	}
}

// PipelineRequest represents a request to the evaluation pipeline.
type PipelineRequest struct {
	// ID is a unique identifier for this request.
	ID string `json:"id"`

	// Command is the command to evaluate (for command evaluation).
	Command string `json:"command,omitempty"`

	// Content is the content to evaluate (for content evaluation).
	Content string `json:"content,omitempty"`

	// ContentType describes what type of content is being evaluated.
	ContentType string `json:"content_type"`

	// Context provides additional context.
	Context PipelineContext `json:"context,omitempty"`

	// PolicyPack is the policy pack to use for evaluation.
	PolicyPack string `json:"policy_pack,omitempty"`

	// RiskTolerance overrides the default risk tolerance for this request.
	// If empty, uses the pipeline's DefaultRiskTolerance.
	RiskTolerance RiskTolerance `json:"risk_tolerance,omitempty"`
}

// PipelineContext provides contextual information for pipeline execution.
type PipelineContext struct {
	// Source indicates the integration source.
	Source string `json:"source,omitempty"`

	// User is the user or process initiating the request.
	User string `json:"user,omitempty"`

	// WorkingDirectory is the current working directory.
	WorkingDirectory string `json:"working_directory,omitempty"`

	// SessionID links related requests.
	SessionID string `json:"session_id,omitempty"`

	// Metadata contains additional context.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// PipelineResponse contains the complete result of pipeline evaluation.
type PipelineResponse struct {
	// RequestID matches the request ID for correlation.
	RequestID string `json:"request_id"`

	// Decision is the final evaluation decision.
	Decision policy.Decision `json:"decision"`

	// RiskScore is the final risk score (0-100).
	RiskScore int `json:"risk_score"`

	// RiskTolerance is the tolerance level that was applied.
	RiskTolerance RiskTolerance `json:"risk_tolerance"`

	// Thresholds shows the thresholds that were used for this evaluation.
	Thresholds RiskThresholds `json:"thresholds"`

	// Reason explains the decision.
	Reason string `json:"reason"`

	// ReasonCode is a machine-readable reason code.
	ReasonCode string `json:"reason_code,omitempty"`

	// PluginsUsed lists all plugins that contributed to the evaluation.
	PluginsUsed []string `json:"plugins_used"`

	// Stages contains detailed results from each pipeline stage.
	Stages PipelineStages `json:"stages"`

	// ProcessingTimeMs is the total processing time.
	ProcessingTimeMs int64 `json:"processing_time_ms"`

	// Findings contains all findings from all scanners.
	Findings []scanners.Finding `json:"findings,omitempty"`

	// ContentClasses are derived classifications.
	ContentClasses []string `json:"content_classes,omitempty"`
}

// PipelineStages contains results from each pipeline stage.
type PipelineStages struct {
	// StaticScan contains results from static scanners.
	StaticScan *StaticScanStage `json:"static_scan,omitempty"`

	// PolicyMatch contains results from policy matching.
	PolicyMatch *PolicyMatchStage `json:"policy_match,omitempty"`

	// AIScoring contains results from AI scoring.
	AIScoring *AIScoringStage `json:"ai_scoring,omitempty"`
}

// StaticScanStage contains results from the static scanning stage.
type StaticScanStage struct {
	// Executed indicates if this stage ran.
	Executed bool `json:"executed"`

	// Findings contains all scanner findings.
	Findings []scanners.Finding `json:"findings,omitempty"`

	// RiskScore is the aggregated risk score from scanners.
	RiskScore int `json:"risk_score"`

	// ScannersUsed lists the scanners that ran.
	ScannersUsed []string `json:"scanners_used"`

	// ProcessingTimeMs is how long scanning took.
	ProcessingTimeMs int64 `json:"processing_time_ms"`
}

// PolicyMatchStage contains results from the policy matching stage.
type PolicyMatchStage struct {
	// Executed indicates if this stage ran.
	Executed bool `json:"executed"`

	// MatchedRules lists the rules that matched.
	MatchedRules []string `json:"matched_rules,omitempty"`

	// Decision is the policy-based decision.
	Decision policy.Decision `json:"decision"`

	// Reason is the policy-based reason.
	Reason string `json:"reason,omitempty"`

	// ProcessingTimeMs is how long matching took.
	ProcessingTimeMs int64 `json:"processing_time_ms"`
}

// AIScoringStage contains results from the AI scoring stage.
type AIScoringStage struct {
	// Executed indicates if this stage ran.
	Executed bool `json:"executed"`

	// Triggered indicates if AI scoring was triggered.
	Triggered bool `json:"triggered"`

	// TriggerReason explains why AI scoring ran or didn't run.
	TriggerReason string `json:"trigger_reason,omitempty"`

	// Assessment contains the AI assessment.
	Assessment *RiskAssessment `json:"assessment,omitempty"`

	// InfluencedDecision indicates if AI changed the decision.
	InfluencedDecision bool `json:"influenced_decision"`

	// OriginalDecision is what the decision was before AI scoring.
	OriginalDecision policy.Decision `json:"original_decision,omitempty"`

	// ProcessingTimeMs is how long AI scoring took.
	ProcessingTimeMs int64 `json:"processing_time_ms"`
}

// EvaluateCommand runs the full pipeline for command evaluation.
func (p *Pipeline) EvaluateCommand(ctx context.Context, req *PipelineRequest) (*PipelineResponse, error) {
	start := time.Now()

	// Determine effective risk tolerance
	tolerance := req.RiskTolerance
	if tolerance == "" {
		tolerance = p.config.DefaultRiskTolerance
	}
	if tolerance == "" {
		tolerance = RiskToleranceBalanced
	}

	resp := &PipelineResponse{
		RequestID:     req.ID,
		RiskTolerance: tolerance,
		Thresholds:    p.getEffectiveThresholds(req),
		PluginsUsed:   make([]string, 0),
		Stages:        PipelineStages{},
	}

	// Stage 1: Static Scanning
	scanResp, err := p.runStaticScan(ctx, req)
	if err != nil && !p.config.FailOpen {
		return nil, fmt.Errorf("static scan failed: %w", err)
	}

	resp.Stages.StaticScan = scanResp
	if scanResp != nil {
		resp.PluginsUsed = append(resp.PluginsUsed, scanResp.ScannersUsed...)
		resp.Findings = scanResp.Findings
		resp.RiskScore = scanResp.RiskScore
	}

	// Stage 2: Policy Matching
	policyResp, err := p.runPolicyMatch(ctx, req, scanResp)
	if err != nil && !p.config.FailOpen {
		return nil, fmt.Errorf("policy match failed: %w", err)
	}

	resp.Stages.PolicyMatch = policyResp
	if policyResp != nil {
		resp.Decision = policyResp.Decision
		resp.Reason = policyResp.Reason
	}

	// Stage 3: AI Scoring (conditional)
	aiResp := p.runAIScoring(ctx, req, resp)
	resp.Stages.AIScoring = aiResp

	if aiResp != nil && aiResp.Executed && aiResp.Assessment != nil {
		resp.PluginsUsed = append(resp.PluginsUsed, aiResp.Assessment.PluginID)

		// Apply AI decision if conditions are met
		if p.shouldApplyAIDecision(resp, aiResp.Assessment) {
			resp.Decision = recommendationToDecision(aiResp.Assessment.Recommendation)
			resp.Reason = aiResp.Assessment.Explanation
			resp.RiskScore = aiResp.Assessment.Score
			aiResp.InfluencedDecision = true
		}
	}

	// Derive content classes from findings
	resp.ContentClasses = deriveContentClasses(resp.Findings)

	resp.ProcessingTimeMs = time.Since(start).Milliseconds()

	return resp, nil
}

// runStaticScan executes all loaded scanners.
func (p *Pipeline) runStaticScan(ctx context.Context, req *PipelineRequest) (*StaticScanStage, error) {
	start := time.Now()

	content := req.Command
	if content == "" {
		content = req.Content
	}

	scanReq := &ScanRequest{
		ID:          req.ID,
		Content:     content,
		ContentType: req.ContentType,
		Context: ScanContext{
			Source:           req.Context.Source,
			User:             req.Context.User,
			WorkingDirectory: req.Context.WorkingDirectory,
			SessionID:        req.Context.SessionID,
			Metadata:         req.Context.Metadata,
		},
	}

	aggResp, err := p.manager.RunScanners(ctx, scanReq)
	if err != nil {
		return nil, err
	}

	return &StaticScanStage{
		Executed:         true,
		Findings:         aggResp.AllFindings,
		RiskScore:        aggResp.AggregatedRiskScore,
		ScannersUsed:     aggResp.ScannersUsed,
		ProcessingTimeMs: time.Since(start).Milliseconds(),
	}, nil
}

// getEffectiveThresholds returns the thresholds to use for a request.
func (p *Pipeline) getEffectiveThresholds(req *PipelineRequest) RiskThresholds {
	// Determine which tolerance level to use
	tolerance := p.config.DefaultRiskTolerance
	if req.RiskTolerance != "" {
		tolerance = req.RiskTolerance
	}
	if tolerance == "" {
		tolerance = RiskToleranceBalanced
	}

	// Check for custom thresholds
	if p.config.CustomThresholds != nil {
		if custom, ok := p.config.CustomThresholds[tolerance]; ok {
			return custom
		}
	}

	// Use default thresholds for this tolerance level
	return DefaultThresholds(tolerance)
}

// containsSeverity checks if a severity is in the list.
func containsSeverity(list []string, severity string) bool {
	for _, s := range list {
		if s == severity {
			return true
		}
	}
	return false
}

// runPolicyMatch evaluates findings against policies using risk tolerance thresholds.
func (p *Pipeline) runPolicyMatch(ctx context.Context, req *PipelineRequest, scanStage *StaticScanStage) (*PolicyMatchStage, error) {
	start := time.Now()

	stage := &PolicyMatchStage{
		Executed: true,
	}

	// Get thresholds based on risk tolerance
	thresholds := p.getEffectiveThresholds(req)

	// Default decision based on risk score
	if scanStage == nil {
		stage.Decision = policy.DecisionAllow
		stage.Reason = "No scanner findings"
		stage.ProcessingTimeMs = time.Since(start).Milliseconds()
		return stage, nil
	}

	// Map risk score to decision using thresholds
	switch {
	case scanStage.RiskScore >= thresholds.DenyThreshold:
		stage.Decision = policy.DecisionDeny
		stage.Reason = fmt.Sprintf("Risk score %d exceeds deny threshold %d", scanStage.RiskScore, thresholds.DenyThreshold)
		stage.MatchedRules = append(stage.MatchedRules, "risk_score_deny")
	case scanStage.RiskScore >= thresholds.AskThreshold:
		stage.Decision = policy.DecisionAsk
		stage.Reason = fmt.Sprintf("Risk score %d exceeds ask threshold %d", scanStage.RiskScore, thresholds.AskThreshold)
		stage.MatchedRules = append(stage.MatchedRules, "risk_score_ask")
	default:
		stage.Decision = policy.DecisionAllow
		stage.Reason = fmt.Sprintf("Risk score %d within acceptable range", scanStage.RiskScore)
	}

	// Check findings against severity thresholds
	for _, f := range scanStage.Findings {
		// Check if severity triggers DENY
		if containsSeverity(thresholds.SeverityDeny, f.Severity) {
			stage.Decision = policy.DecisionDeny
			stage.Reason = fmt.Sprintf("%s severity finding: %s", f.Severity, f.Message)
			stage.MatchedRules = append(stage.MatchedRules, fmt.Sprintf("severity_%s_deny", f.Severity))
			break
		}
		// Check if severity triggers ASK (only if not already denying)
		if stage.Decision != policy.DecisionDeny && containsSeverity(thresholds.SeverityAsk, f.Severity) {
			stage.Decision = policy.DecisionAsk
			stage.Reason = fmt.Sprintf("%s severity finding: %s", f.Severity, f.Message)
			stage.MatchedRules = append(stage.MatchedRules, fmt.Sprintf("severity_%s_ask", f.Severity))
		}
	}

	stage.ProcessingTimeMs = time.Since(start).Milliseconds()
	return stage, nil
}

// runAIScoring conditionally executes AI assessment.
func (p *Pipeline) runAIScoring(ctx context.Context, req *PipelineRequest, resp *PipelineResponse) *AIScoringStage {
	stage := &AIScoringStage{
		Executed:         false,
		OriginalDecision: resp.Decision,
	}

	// Check if AI scoring is enabled
	if !p.config.AIScoring.Enabled {
		stage.TriggerReason = "AI scoring disabled"
		return stage
	}

	// Check if LLM is available
	if !p.manager.IsLLMAvailable(ctx) {
		stage.TriggerReason = "LLM provider not available"
		return stage
	}

	// Check trigger conditions
	triggered, reason := p.checkAITriggerConditions(resp)
	if !triggered {
		stage.TriggerReason = reason
		return stage
	}

	stage.Triggered = true
	stage.TriggerReason = reason
	stage.Executed = true

	start := time.Now()

	// Build assessment request
	assessReq := &CommandAssessmentRequest{
		ID:      req.ID,
		Command: req.Command,
		Context: CommandContext{
			WorkingDirectory: req.Context.WorkingDirectory,
			User:             req.Context.User,
			Source:           req.Context.Source,
		},
		ScanResults: &AggregatedScanResponse{
			RequestID:           req.ID,
			AllFindings:         resp.Findings,
			AggregatedRiskScore: resp.RiskScore,
		},
	}

	assessment, err := p.manager.AssessCommand(ctx, assessReq)
	if err != nil {
		stage.TriggerReason = fmt.Sprintf("AI assessment failed: %v", err)
		stage.Executed = false
		return stage
	}

	stage.Assessment = assessment
	stage.ProcessingTimeMs = time.Since(start).Milliseconds()

	return stage
}

// checkAITriggerConditions evaluates if AI scoring should run.
func (p *Pipeline) checkAITriggerConditions(resp *PipelineResponse) (bool, string) {
	if len(p.config.AIScoring.TriggerConditions) == 0 {
		return true, "No conditions (always trigger)"
	}

	for _, cond := range p.config.AIScoring.TriggerConditions {
		switch cond.Type {
		case AITriggerAlways:
			return true, "Always trigger"
		case AITriggerRiskScoreGTE:
			if resp.RiskScore >= cond.Value {
				return true, fmt.Sprintf("Risk score %d >= %d", resp.RiskScore, cond.Value)
			}
		case AITriggerRiskScoreLTE:
			if resp.RiskScore <= cond.Value {
				return true, fmt.Sprintf("Risk score %d <= %d", resp.RiskScore, cond.Value)
			}
		case AITriggerDecisionEquals:
			if resp.Decision == cond.Decision {
				return true, fmt.Sprintf("Decision is %s", cond.Decision)
			}
		case AITriggerHasFindings:
			if len(resp.Findings) > 0 {
				return true, "Has findings"
			}
		}
	}

	return false, "No trigger conditions met"
}

// shouldApplyAIDecision determines if the AI decision should override the current decision.
func (p *Pipeline) shouldApplyAIDecision(resp *PipelineResponse, assessment *RiskAssessment) bool {
	// Check minimum confidence
	if assessment.Confidence < p.config.AIScoring.MinConfidence {
		return false
	}

	aiDecision := recommendationToDecision(assessment.Recommendation)

	// If upgrade only, AI can only make decisions more restrictive
	if p.config.AIScoring.UpgradeOnly {
		return decisionPriority(aiDecision) > decisionPriority(resp.Decision)
	}

	return true
}

// recommendationToDecision converts an LLM recommendation to a policy decision.
func recommendationToDecision(rec Recommendation) policy.Decision {
	switch rec {
	case RecommendationAllow:
		return policy.DecisionAllow
	case RecommendationDeny:
		return policy.DecisionDeny
	case RecommendationAsk:
		return policy.DecisionAsk
	case RecommendationModify:
		return policy.DecisionTransform
	case RecommendationMonitor:
		return policy.DecisionLogOnly
	default:
		return policy.DecisionAsk
	}
}

// decisionPriority returns a numeric priority for decision comparison.
func decisionPriority(d policy.Decision) int {
	switch d {
	case policy.DecisionDeny:
		return 5
	case policy.DecisionAsk:
		return 4
	case policy.DecisionRedact:
		return 3
	case policy.DecisionTransform:
		return 2
	case policy.DecisionLogOnly:
		return 1
	case policy.DecisionAllow:
		return 0
	default:
		return 0
	}
}

// deriveContentClasses extracts content classes from findings.
func deriveContentClasses(findings []scanners.Finding) []string {
	classSet := make(map[string]struct{})
	for _, f := range findings {
		classSet[string(f.Category)] = struct{}{}
	}

	classes := make([]string, 0, len(classSet))
	for class := range classSet {
		classes = append(classes, class)
	}
	return classes
}

// EvaluateContent runs the pipeline for generic content evaluation.
func (p *Pipeline) EvaluateContent(ctx context.Context, req *PipelineRequest) (*PipelineResponse, error) {
	// Content evaluation uses the same pipeline as command evaluation
	return p.EvaluateCommand(ctx, req)
}

// QuickEvaluate performs a fast evaluation with scanners only (no AI).
func (p *Pipeline) QuickEvaluate(ctx context.Context, req *PipelineRequest) (*PipelineResponse, error) {
	start := time.Now()

	resp := &PipelineResponse{
		RequestID:   req.ID,
		PluginsUsed: make([]string, 0),
		Stages:      PipelineStages{},
	}

	// Only run static scanning
	scanResp, err := p.runStaticScan(ctx, req)
	if err != nil && !p.config.FailOpen {
		return nil, fmt.Errorf("static scan failed: %w", err)
	}

	resp.Stages.StaticScan = scanResp
	if scanResp != nil {
		resp.PluginsUsed = append(resp.PluginsUsed, scanResp.ScannersUsed...)
		resp.Findings = scanResp.Findings
		resp.RiskScore = scanResp.RiskScore
	}

	// Simple policy matching
	policyResp, _ := p.runPolicyMatch(ctx, req, scanResp)
	resp.Stages.PolicyMatch = policyResp
	if policyResp != nil {
		resp.Decision = policyResp.Decision
		resp.Reason = policyResp.Reason
	}

	resp.ContentClasses = deriveContentClasses(resp.Findings)
	resp.ProcessingTimeMs = time.Since(start).Milliseconds()

	return resp, nil
}
