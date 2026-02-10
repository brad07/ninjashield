package plugin

import (
	"context"
	"testing"
	"time"

	"github.com/brad07/ninjashield/pkg/policy"
	"github.com/brad07/ninjashield/pkg/scanners"
)

func TestPipeline(t *testing.T) {
	// Create registry and manager
	registry := NewRegistry()

	// Register mock scanners with different findings
	registry.RegisterScanner("high_risk", func() ScannerPlugin {
		return NewMockScanner("scanner:high_risk", 100, []scanners.Finding{
			{Type: "dangerous_pattern", Category: "destructive", Severity: "critical", Confidence: 0.95, Message: "Dangerous command detected"},
		})
	})
	registry.RegisterScanner("low_risk", func() ScannerPlugin {
		return NewMockScanner("scanner:low_risk", 50, []scanners.Finding{
			{Type: "info", Category: "informational", Severity: "low", Confidence: 0.8, Message: "Informational finding"},
		})
	})

	config := DefaultManagerConfig()
	manager := NewManager(registry, config, nil)
	ctx := context.Background()

	// Load scanners
	manager.LoadScanner(ctx, "high_risk", nil)
	manager.LoadScanner(ctx, "low_risk", nil)

	// Create pipeline
	pipelineConfig := DefaultPipelineConfig()
	pipelineConfig.AIScoring.Enabled = false // Disable AI for this test
	pipeline := NewPipeline(manager, pipelineConfig)

	// Test with dangerous command
	req := &PipelineRequest{
		ID:          "test-1",
		Command:     "rm -rf /",
		ContentType: "command",
		Context: PipelineContext{
			Source: "test",
		},
	}

	resp, err := pipeline.EvaluateCommand(ctx, req)
	if err != nil {
		t.Fatalf("EvaluateCommand failed: %v", err)
	}

	// Verify response
	if resp.RequestID != "test-1" {
		t.Errorf("Expected request ID 'test-1', got %s", resp.RequestID)
	}

	// Should be DENY due to critical severity
	if resp.Decision != policy.DecisionDeny {
		t.Errorf("Expected decision DENY, got %s", resp.Decision)
	}

	// Should have findings from both scanners
	if len(resp.Findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(resp.Findings))
	}

	// Should have used both scanners
	if len(resp.PluginsUsed) != 2 {
		t.Errorf("Expected 2 plugins used, got %d", len(resp.PluginsUsed))
	}

	// Verify stages
	if resp.Stages.StaticScan == nil || !resp.Stages.StaticScan.Executed {
		t.Error("Static scan stage should have executed")
	}
	if resp.Stages.PolicyMatch == nil || !resp.Stages.PolicyMatch.Executed {
		t.Error("Policy match stage should have executed")
	}
}

func TestPipelineQuickEvaluate(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterScanner("mock", func() ScannerPlugin {
		return NewMockScanner("scanner:mock", 50, []scanners.Finding{
			{Type: "test", Category: "test", Severity: "medium", Confidence: 0.7, Message: "Test"},
		})
	})

	manager := NewManager(registry, DefaultManagerConfig(), nil)
	ctx := context.Background()
	manager.LoadScanner(ctx, "mock", nil)

	pipelineConfig := DefaultPipelineConfig()
	pipelineConfig.AIScoring.Enabled = false
	pipeline := NewPipeline(manager, pipelineConfig)

	req := &PipelineRequest{
		ID:      "quick-test",
		Command: "ls -la",
	}

	resp, err := pipeline.QuickEvaluate(ctx, req)
	if err != nil {
		t.Fatalf("QuickEvaluate failed: %v", err)
	}

	// Quick evaluate should not run AI scoring
	if resp.Stages.AIScoring != nil && resp.Stages.AIScoring.Executed {
		t.Error("AI scoring should not have executed in quick mode")
	}

	// Should still have scanner results
	if resp.Stages.StaticScan == nil || !resp.Stages.StaticScan.Executed {
		t.Error("Static scan should have executed")
	}
}

func TestPipelineNoScanners(t *testing.T) {
	registry := NewRegistry()
	manager := NewManager(registry, DefaultManagerConfig(), nil)

	pipelineConfig := DefaultPipelineConfig()
	pipelineConfig.AIScoring.Enabled = false
	pipeline := NewPipeline(manager, pipelineConfig)

	ctx := context.Background()
	req := &PipelineRequest{
		ID:      "empty-test",
		Command: "echo hello",
	}

	resp, err := pipeline.EvaluateCommand(ctx, req)
	if err != nil {
		t.Fatalf("EvaluateCommand failed: %v", err)
	}

	// Should allow with no findings
	if resp.Decision != policy.DecisionAllow {
		t.Errorf("Expected decision ALLOW, got %s", resp.Decision)
	}
	if len(resp.Findings) != 0 {
		t.Errorf("Expected 0 findings, got %d", len(resp.Findings))
	}
}

func TestPipelineRiskScoreDecision(t *testing.T) {
	// Test with balanced tolerance (default)
	// Balanced thresholds: DenyThreshold=75, AskThreshold=50
	// MockScanner uses scanners.Aggregate to calculate risk score from severity:
	// - critical → 100, high → 75, medium → 50, low → 25
	tests := []struct {
		name         string
		severity     string
		expectedDec  policy.Decision
	}{
		{"critical", "critical", policy.DecisionDeny},  // score 100 >= DenyThreshold (75)
		{"high", "high", policy.DecisionDeny},          // score 75 >= DenyThreshold (75)
		{"medium", "medium", policy.DecisionAsk},       // score 50 >= AskThreshold (50)
		{"low", "low", policy.DecisionAllow},           // score 25 < AskThreshold (50)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()
			registry.RegisterScanner("test", func() ScannerPlugin {
				return NewMockScanner("scanner:test", 50, []scanners.Finding{
					{Type: "test", Category: "test", Severity: tc.severity, Confidence: 0.9, Message: "Test"},
				})
			})

			manager := NewManager(registry, DefaultManagerConfig(), nil)
			ctx := context.Background()
			manager.LoadScanner(ctx, "test", nil)

			pipelineConfig := DefaultPipelineConfig()
			pipelineConfig.AIScoring.Enabled = false
			pipeline := NewPipeline(manager, pipelineConfig)

			req := &PipelineRequest{ID: "test", Command: "test"}
			resp, err := pipeline.EvaluateCommand(ctx, req)
			if err != nil {
				t.Fatalf("EvaluateCommand failed: %v", err)
			}

			if resp.Decision != tc.expectedDec {
				t.Errorf("Expected decision %s for severity %s, got %s", tc.expectedDec, tc.severity, resp.Decision)
			}
		})
	}
}

func TestRiskToleranceLevels(t *testing.T) {
	tests := []struct {
		name           string
		tolerance      RiskTolerance
		riskScore      int
		severity       string
		expectedDec    policy.Decision
	}{
		// Strict tolerance: deny >= 50, ask >= 25, deny on high/critical
		{"strict_high_score", RiskToleranceStrict, 60, "low", policy.DecisionDeny},
		{"strict_medium_score", RiskToleranceStrict, 30, "low", policy.DecisionAsk},
		{"strict_low_score", RiskToleranceStrict, 20, "low", policy.DecisionAllow},
		{"strict_high_severity", RiskToleranceStrict, 10, "high", policy.DecisionDeny},

		// Balanced tolerance: deny >= 75, ask >= 50, deny on critical only
		{"balanced_high_score", RiskToleranceBalanced, 80, "low", policy.DecisionDeny},
		{"balanced_medium_score", RiskToleranceBalanced, 60, "low", policy.DecisionAsk},
		{"balanced_low_score", RiskToleranceBalanced, 40, "low", policy.DecisionAllow},
		{"balanced_high_severity", RiskToleranceBalanced, 10, "high", policy.DecisionAsk},

		// Permissive tolerance: deny >= 90, ask >= 75, deny on critical only
		{"permissive_high_score", RiskTolerancePermissive, 95, "low", policy.DecisionDeny},
		{"permissive_medium_score", RiskTolerancePermissive, 80, "low", policy.DecisionAsk},
		{"permissive_low_score", RiskTolerancePermissive, 60, "low", policy.DecisionAllow},
		{"permissive_high_severity", RiskTolerancePermissive, 10, "high", policy.DecisionAsk},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewRegistry()

			// Create scanner that returns specific risk score and severity
			registry.RegisterScanner("test", func() ScannerPlugin {
				return &MockScannerWithScore{
					MockScanner: *NewMockScanner("scanner:test", 50, []scanners.Finding{
						{Type: "test", Category: "test", Severity: tc.severity, Confidence: 0.9, Message: "Test"},
					}),
					riskScore: tc.riskScore,
				}
			})

			manager := NewManager(registry, DefaultManagerConfig(), nil)
			ctx := context.Background()
			manager.LoadScanner(ctx, "test", nil)

			pipelineConfig := DefaultPipelineConfig()
			pipelineConfig.AIScoring.Enabled = false
			pipelineConfig.DefaultRiskTolerance = tc.tolerance
			pipeline := NewPipeline(manager, pipelineConfig)

			req := &PipelineRequest{ID: "test", Command: "test"}
			resp, err := pipeline.EvaluateCommand(ctx, req)
			if err != nil {
				t.Fatalf("EvaluateCommand failed: %v", err)
			}

			if resp.Decision != tc.expectedDec {
				t.Errorf("Expected decision %s for tolerance %s, score %d, severity %s; got %s",
					tc.expectedDec, tc.tolerance, tc.riskScore, tc.severity, resp.Decision)
			}

			// Verify tolerance is in response
			if resp.RiskTolerance != tc.tolerance {
				t.Errorf("Expected tolerance %s in response, got %s", tc.tolerance, resp.RiskTolerance)
			}
		})
	}
}

func TestRiskTolerancePerRequest(t *testing.T) {
	registry := NewRegistry()
	registry.RegisterScanner("test", func() ScannerPlugin {
		return &MockScannerWithScore{
			MockScanner: *NewMockScanner("scanner:test", 50, []scanners.Finding{
				{Type: "test", Category: "test", Severity: "medium", Confidence: 0.9, Message: "Test"},
			}),
			riskScore: 60, // This would be ASK in balanced, DENY in strict, ALLOW in permissive
		}
	})

	manager := NewManager(registry, DefaultManagerConfig(), nil)
	ctx := context.Background()
	manager.LoadScanner(ctx, "test", nil)

	pipelineConfig := DefaultPipelineConfig()
	pipelineConfig.AIScoring.Enabled = false
	pipelineConfig.DefaultRiskTolerance = RiskToleranceBalanced
	pipeline := NewPipeline(manager, pipelineConfig)

	// Test with default (balanced) - should ASK
	req1 := &PipelineRequest{ID: "test1", Command: "test"}
	resp1, _ := pipeline.EvaluateCommand(ctx, req1)
	if resp1.Decision != policy.DecisionAsk {
		t.Errorf("Default tolerance should ASK, got %s", resp1.Decision)
	}

	// Override with strict - should DENY
	req2 := &PipelineRequest{ID: "test2", Command: "test", RiskTolerance: RiskToleranceStrict}
	resp2, _ := pipeline.EvaluateCommand(ctx, req2)
	if resp2.Decision != policy.DecisionDeny {
		t.Errorf("Strict tolerance should DENY, got %s", resp2.Decision)
	}

	// Override with permissive - should ALLOW
	req3 := &PipelineRequest{ID: "test3", Command: "test", RiskTolerance: RiskTolerancePermissive}
	resp3, _ := pipeline.EvaluateCommand(ctx, req3)
	if resp3.Decision != policy.DecisionAllow {
		t.Errorf("Permissive tolerance should ALLOW, got %s", resp3.Decision)
	}
}

// MockScannerWithScore allows setting a specific risk score
type MockScannerWithScore struct {
	MockScanner
	riskScore int
}

func (m *MockScannerWithScore) Scan(ctx context.Context, req *ScanRequest) (*ScanResponse, error) {
	return &ScanResponse{
		RequestID:        req.ID,
		PluginID:         m.info.ID,
		Findings:         m.findings,
		RiskScore:        m.riskScore,
		ProcessingTimeMs: 1,
	}, nil
}

func TestDefaultThresholds(t *testing.T) {
	strict := DefaultThresholds(RiskToleranceStrict)
	if strict.DenyThreshold != 50 || strict.AskThreshold != 25 {
		t.Errorf("Strict thresholds wrong: deny=%d, ask=%d", strict.DenyThreshold, strict.AskThreshold)
	}

	balanced := DefaultThresholds(RiskToleranceBalanced)
	if balanced.DenyThreshold != 75 || balanced.AskThreshold != 50 {
		t.Errorf("Balanced thresholds wrong: deny=%d, ask=%d", balanced.DenyThreshold, balanced.AskThreshold)
	}

	permissive := DefaultThresholds(RiskTolerancePermissive)
	if permissive.DenyThreshold != 90 || permissive.AskThreshold != 75 {
		t.Errorf("Permissive thresholds wrong: deny=%d, ask=%d", permissive.DenyThreshold, permissive.AskThreshold)
	}
}

func TestAITriggerConditions(t *testing.T) {
	pipelineConfig := DefaultPipelineConfig()
	pipelineConfig.AIScoring.Enabled = true
	pipelineConfig.AIScoring.TriggerConditions = []AITriggerCondition{
		{Type: AITriggerRiskScoreGTE, Value: 50},
	}

	// We can't fully test AI scoring without an LLM, but we can test trigger logic
	pipeline := &Pipeline{config: pipelineConfig}

	// Test with score >= 50
	resp := &PipelineResponse{RiskScore: 60, Decision: policy.DecisionAsk}
	triggered, reason := pipeline.checkAITriggerConditions(resp)
	if !triggered {
		t.Error("Expected AI to be triggered for score 60")
	}
	if reason == "" {
		t.Error("Expected non-empty trigger reason")
	}

	// Test with score < 50
	resp.RiskScore = 30
	triggered, _ = pipeline.checkAITriggerConditions(resp)
	if triggered {
		t.Error("Expected AI not to be triggered for score 30")
	}
}

func TestDecisionPriority(t *testing.T) {
	// DENY should have highest priority
	if decisionPriority(policy.DecisionDeny) <= decisionPriority(policy.DecisionAsk) {
		t.Error("DENY should have higher priority than ASK")
	}
	if decisionPriority(policy.DecisionAsk) <= decisionPriority(policy.DecisionAllow) {
		t.Error("ASK should have higher priority than ALLOW")
	}
}

func TestRecommendationToDecision(t *testing.T) {
	tests := []struct {
		rec      Recommendation
		expected policy.Decision
	}{
		{RecommendationAllow, policy.DecisionAllow},
		{RecommendationDeny, policy.DecisionDeny},
		{RecommendationAsk, policy.DecisionAsk},
		{RecommendationModify, policy.DecisionTransform},
		{RecommendationMonitor, policy.DecisionLogOnly},
		{Recommendation("unknown"), policy.DecisionAsk},
	}

	for _, tc := range tests {
		result := recommendationToDecision(tc.rec)
		if result != tc.expected {
			t.Errorf("recommendationToDecision(%s) = %s, expected %s", tc.rec, result, tc.expected)
		}
	}
}

func TestDefaultPipelineConfig(t *testing.T) {
	cfg := DefaultPipelineConfig()

	if !cfg.ParallelScanners {
		t.Error("Expected parallel scanners to be enabled by default")
	}
	if cfg.ScannerTimeout != 5*time.Second {
		t.Errorf("Expected scanner timeout 5s, got %v", cfg.ScannerTimeout)
	}
	if cfg.LLMTimeout != 30*time.Second {
		t.Errorf("Expected LLM timeout 30s, got %v", cfg.LLMTimeout)
	}
	if cfg.FailOpen {
		t.Error("Expected fail open to be false by default")
	}
	if !cfg.AIScoring.Enabled {
		t.Error("Expected AI scoring to be enabled by default")
	}
	if !cfg.AIScoring.UpgradeOnly {
		t.Error("Expected AI scoring upgrade only to be true by default")
	}
}
