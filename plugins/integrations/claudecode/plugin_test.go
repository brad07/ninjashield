package claudecode

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/brad07/ninjashield/pkg/plugin"
	"github.com/brad07/ninjashield/pkg/policy"
)

func TestClaudeCodeIntegrationInfo(t *testing.T) {
	integration := New()

	info := integration.Info()
	if info.ID != "integration:claude-code" {
		t.Errorf("Expected ID 'integration:claude-code', got %s", info.ID)
	}
	if info.Type != plugin.PluginTypeIntegration {
		t.Errorf("Expected type integration, got %s", info.Type)
	}
}

func TestClaudeCodeIntegrationType(t *testing.T) {
	integration := New().(*ClaudeCodeIntegration)

	if integration.Type() != plugin.IntegrationTypeCLIHook {
		t.Errorf("Expected type cli_hook, got %s", integration.Type())
	}
}

func TestClaudeCodeParseRequest(t *testing.T) {
	integration := New().(*ClaudeCodeIntegration)

	ctx := context.Background()
	integration.Init(ctx, nil)

	tests := []struct {
		name        string
		input       ClaudeCodeInput
		wantType    string
		wantCommand string
	}{
		{
			name: "bash command",
			input: ClaudeCodeInput{
				ToolName:  "Bash",
				ToolInput: json.RawMessage(`{"command": "echo hello", "description": "Print greeting"}`),
				SessionID: "sess-123",
				CWD:       "/home/user",
			},
			wantType:    "command",
			wantCommand: "echo hello",
		},
		{
			name: "write file",
			input: ClaudeCodeInput{
				ToolName:  "Write",
				ToolInput: json.RawMessage(`{"file_path": "/tmp/test.txt", "content": "test content"}`),
				SessionID: "sess-123",
				CWD:       "/home/user",
			},
			wantType:    "file_write",
			wantCommand: "",
		},
		{
			name: "other tool",
			input: ClaudeCodeInput{
				ToolName:  "Read",
				ToolInput: json.RawMessage(`{"file_path": "/etc/passwd"}`),
				SessionID: "sess-123",
				CWD:       "/home/user",
			},
			wantType:    "tool_call",
			wantCommand: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, _ := json.Marshal(tc.input)
			req, err := integration.ParseRequest(ctx, input)
			if err != nil {
				t.Fatalf("ParseRequest failed: %v", err)
			}

			if req.RequestType != tc.wantType {
				t.Errorf("Expected request type %s, got %s", tc.wantType, req.RequestType)
			}
			if req.Payload.Command != tc.wantCommand {
				t.Errorf("Expected command %s, got %s", tc.wantCommand, req.Payload.Command)
			}
			if req.Payload.ToolName != tc.input.ToolName {
				t.Errorf("Expected tool name %s, got %s", tc.input.ToolName, req.Payload.ToolName)
			}
			if req.Context.SessionID != tc.input.SessionID {
				t.Errorf("Expected session ID %s, got %s", tc.input.SessionID, req.Context.SessionID)
			}
		})
	}
}

func TestClaudeCodeFormatResponse(t *testing.T) {
	integration := New().(*ClaudeCodeIntegration)

	ctx := context.Background()
	integration.Init(ctx, nil)

	tests := []struct {
		name         string
		decision     policy.Decision
		riskScore    int
		wantAllowed  bool
		wantDecision string
	}{
		{
			name:         "allow",
			decision:     policy.DecisionAllow,
			riskScore:    10,
			wantAllowed:  true,
			wantDecision: "allow",
		},
		{
			name:         "deny",
			decision:     policy.DecisionDeny,
			riskScore:    90,
			wantAllowed:  false,
			wantDecision: "deny",
		},
		{
			name:         "ask",
			decision:     policy.DecisionAsk,
			riskScore:    50,
			wantAllowed:  false,
			wantDecision: "ask",
		},
		{
			name:         "transform",
			decision:     policy.DecisionTransform,
			riskScore:    30,
			wantAllowed:  true,
			wantDecision: "allow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &plugin.IntegrationRequest{
				ID: "test-123",
			}
			pipelineResp := &plugin.PipelineResponse{
				Decision:  tc.decision,
				RiskScore: tc.riskScore,
			}

			resp, err := integration.FormatResponse(ctx, req, pipelineResp)
			if err != nil {
				t.Fatalf("FormatResponse failed: %v", err)
			}

			if resp.Allowed != tc.wantAllowed {
				t.Errorf("Expected allowed %v, got %v", tc.wantAllowed, resp.Allowed)
			}
			if resp.Decision != tc.wantDecision {
				t.Errorf("Expected decision %s, got %s", tc.wantDecision, resp.Decision)
			}
			if resp.RiskScore != tc.riskScore {
				t.Errorf("Expected risk score %d, got %d", tc.riskScore, resp.RiskScore)
			}
		})
	}
}

func TestClaudeCodeValidateConfig(t *testing.T) {
	integration := New().(*ClaudeCodeIntegration)

	// Valid config
	validConfig := map[string]any{
		"risk_tolerance": "strict",
	}
	if err := integration.ValidateConfig(validConfig); err != nil {
		t.Errorf("Expected valid config to pass: %v", err)
	}

	// Invalid risk tolerance
	invalidConfig := map[string]any{
		"risk_tolerance": "invalid",
	}
	if err := integration.ValidateConfig(invalidConfig); err == nil {
		t.Error("Expected invalid risk tolerance to fail")
	}
}

func TestClaudeCodeSupportedRequestTypes(t *testing.T) {
	integration := New().(*ClaudeCodeIntegration)

	types := integration.SupportedRequestTypes()
	if len(types) == 0 {
		t.Error("Expected at least one supported request type")
	}

	// Check for expected types
	hasCommand := false
	for _, typ := range types {
		if typ == "command" {
			hasCommand = true
		}
	}
	if !hasCommand {
		t.Error("Expected 'command' to be a supported request type")
	}
}

func TestToClaudeCodeOutput(t *testing.T) {
	tests := []struct {
		name         string
		resp         *plugin.IntegrationResponse
		wantDecision string
		wantReason   string
	}{
		{
			name: "allow without reason",
			resp: &plugin.IntegrationResponse{
				Decision: "allow",
			},
			wantDecision: "allow",
			wantReason:   "",
		},
		{
			name: "deny with reason",
			resp: &plugin.IntegrationResponse{
				Decision: "deny",
				Reason:   "Dangerous command",
			},
			wantDecision: "deny",
			wantReason:   "Dangerous command",
		},
		{
			name: "allow with modified input",
			resp: &plugin.IntegrationResponse{
				Decision: "allow",
				ModifiedPayload: &plugin.IntegrationPayload{
					Command: "echo [REDACTED]",
				},
			},
			wantDecision: "allow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := ToClaudeCodeOutput(tc.resp)

			if output.HookSpecificOutput.PermissionDecision != tc.wantDecision {
				t.Errorf("Expected decision %s, got %s", tc.wantDecision, output.HookSpecificOutput.PermissionDecision)
			}
			if output.HookSpecificOutput.PermissionDecisionReason != tc.wantReason {
				t.Errorf("Expected reason %s, got %s", tc.wantReason, output.HookSpecificOutput.PermissionDecisionReason)
			}
			if output.HookSpecificOutput.HookEventName != "PreToolUse" {
				t.Errorf("Expected hook event name 'PreToolUse', got %s", output.HookSpecificOutput.HookEventName)
			}

			// Check modified input
			if tc.resp.ModifiedPayload != nil && tc.resp.ModifiedPayload.Command != "" {
				if output.HookSpecificOutput.UpdatedInput == nil {
					t.Error("Expected updated input to be set")
				} else if output.HookSpecificOutput.UpdatedInput["command"] != tc.resp.ModifiedPayload.Command {
					t.Errorf("Expected updated command %s, got %v", tc.resp.ModifiedPayload.Command, output.HookSpecificOutput.UpdatedInput["command"])
				}
			}
		})
	}
}

func TestMarshalClaudeCodeResponse(t *testing.T) {
	resp := &plugin.IntegrationResponse{
		RequestID: "test-123",
		Allowed:   true,
		Decision:  "allow",
		RiskScore: 10,
	}

	data, err := MarshalClaudeCodeResponse(resp)
	if err != nil {
		t.Fatalf("MarshalClaudeCodeResponse failed: %v", err)
	}

	// Verify it's valid JSON
	var output ClaudeCodeOutput
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if output.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("Expected decision 'allow', got %s", output.HookSpecificOutput.PermissionDecision)
	}
}

func TestClaudeCodeToolEvaluation(t *testing.T) {
	integration := New().(*ClaudeCodeIntegration)

	ctx := context.Background()
	integration.Init(ctx, nil)

	// Default evaluated tools are Bash, Write, Edit, NotebookEdit
	if !integration.shouldEvaluateTool("Bash") {
		t.Error("Expected Bash to be evaluated")
	}
	if !integration.shouldEvaluateTool("Write") {
		t.Error("Expected Write to be evaluated")
	}
	if integration.shouldEvaluateTool("Read") {
		t.Error("Expected Read to not be evaluated by default")
	}
}

func TestClaudeCodeAllowedBlockedTools(t *testing.T) {
	integration := New().(*ClaudeCodeIntegration)

	ctx := context.Background()
	config := map[string]any{
		"allowed_tools": []string{"safe-command"},
		"blocked_tools": []string{"dangerous-command"},
	}
	integration.Init(ctx, config)

	if !integration.IsToolAllowed("safe-command") {
		t.Error("Expected safe-command to be allowed")
	}
	if !integration.IsToolBlocked("dangerous-command") {
		t.Error("Expected dangerous-command to be blocked")
	}
}
