// Package claudecode provides the Claude Code integration plugin for NinjaShield.
package claudecode

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/brad07/ninjashield/pkg/plugin"
	"github.com/brad07/ninjashield/pkg/policy"
)

func init() {
	plugin.RegisterIntegration("claude-code", New)
}

// ClaudeCodeInput represents the input from Claude Code hooks.
type ClaudeCodeInput struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	SessionID string          `json:"session_id"`
	CWD       string          `json:"cwd"`
}

// BashToolInput represents the input for Bash tool calls.
type BashToolInput struct {
	Command     string `json:"command"`
	Description string `json:"description,omitempty"`
	Timeout     int    `json:"timeout,omitempty"`
}

// WriteToolInput represents the input for Write/Edit tool calls.
type WriteToolInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content,omitempty"`
}

// ClaudeCodeOutput represents the output format for Claude Code hooks.
type ClaudeCodeOutput struct {
	HookSpecificOutput HookSpecificOutput `json:"hookSpecificOutput"`
}

// HookSpecificOutput contains the hook response details.
type HookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

// ClaudeCodeIntegration implements the IntegrationPlugin interface for Claude Code.
type ClaudeCodeIntegration struct {
	*plugin.BaseIntegration
	evaluatedTools []string
}

// New creates a new Claude Code integration plugin.
func New() plugin.IntegrationPlugin {
	return &ClaudeCodeIntegration{
		BaseIntegration: plugin.NewBaseIntegration("claude-code", "Claude Code Integration", plugin.IntegrationTypeCLIHook),
		evaluatedTools:  []string{"Bash", "Write", "Edit", "NotebookEdit"},
	}
}

// Type returns the integration type.
func (c *ClaudeCodeIntegration) Type() plugin.IntegrationType {
	return plugin.IntegrationTypeCLIHook
}

// Init initializes the Claude Code integration.
func (c *ClaudeCodeIntegration) Init(ctx context.Context, config map[string]any) error {
	if err := c.BaseIntegration.Init(ctx, config); err != nil {
		return err
	}

	// Parse evaluated tools from config if provided
	if tools, ok := config["evaluated_tools"].([]string); ok {
		c.evaluatedTools = tools
	}

	return nil
}

// ParseRequest parses Claude Code hook input into an IntegrationRequest.
func (c *ClaudeCodeIntegration) ParseRequest(ctx context.Context, raw []byte) (*plugin.IntegrationRequest, error) {
	var input ClaudeCodeInput
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, fmt.Errorf("failed to parse Claude Code input: %w", err)
	}

	req := &plugin.IntegrationRequest{
		ID:            fmt.Sprintf("cc-%d", time.Now().UnixNano()),
		IntegrationID: "claude-code",
		Timestamp:     time.Now(),
		Payload: plugin.IntegrationPayload{
			ToolName:  input.ToolName,
			ToolInput: make(map[string]any),
			Raw:       raw,
		},
		Context: plugin.IntegrationContext{
			SessionID:        input.SessionID,
			WorkingDirectory: input.CWD,
		},
	}

	// Parse tool-specific input
	switch input.ToolName {
	case "Bash":
		var bashInput BashToolInput
		if err := json.Unmarshal(input.ToolInput, &bashInput); err == nil {
			req.RequestType = "command"
			req.Payload.Command = bashInput.Command
			req.Payload.ContentType = "shell_command"
			req.Payload.ToolInput["command"] = bashInput.Command
			req.Payload.ToolInput["description"] = bashInput.Description
		}

	case "Write", "Edit":
		var writeInput WriteToolInput
		if err := json.Unmarshal(input.ToolInput, &writeInput); err == nil {
			req.RequestType = "file_write"
			req.Payload.FilePath = writeInput.FilePath
			req.Payload.FileContent = writeInput.Content
			req.Payload.ContentType = "file_content"
			req.Payload.ToolInput["file_path"] = writeInput.FilePath
			req.Payload.ToolInput["content"] = writeInput.Content
		}

	default:
		req.RequestType = "tool_call"
		// Try to unmarshal generic tool input
		var genericInput map[string]any
		if err := json.Unmarshal(input.ToolInput, &genericInput); err == nil {
			req.Payload.ToolInput = genericInput
		}
	}

	return req, nil
}

// FormatResponse formats a PipelineResponse into Claude Code's expected output.
func (c *ClaudeCodeIntegration) FormatResponse(ctx context.Context, req *plugin.IntegrationRequest, resp *plugin.PipelineResponse) (*plugin.IntegrationResponse, error) {
	integrationResp := &plugin.IntegrationResponse{
		RequestID:        req.ID,
		RiskScore:        resp.RiskScore,
		ProcessingTimeMs: resp.ProcessingTimeMs,
	}

	// Map pipeline decision to integration response
	switch resp.Decision {
	case policy.DecisionAllow:
		integrationResp.Allowed = true
		integrationResp.Decision = "allow"

	case policy.DecisionDeny:
		integrationResp.Allowed = false
		integrationResp.Decision = "deny"
		if resp.Reason != "" {
			integrationResp.Reason = fmt.Sprintf("⚠️ NINJASHIELD DENIED (Risk: %d) - %s", resp.RiskScore, resp.Reason)
		} else {
			integrationResp.Reason = fmt.Sprintf("⚠️ NINJASHIELD DENIED (Risk: %d) - Command flagged by security policy", resp.RiskScore)
		}

	case policy.DecisionTransform:
		integrationResp.Allowed = true
		integrationResp.Decision = "allow"
		// Transform decision indicates a modified command would be used
		// The modified command would typically come from a redaction or transformation stage

	case policy.DecisionAsk, policy.DecisionLogOnly:
		integrationResp.Allowed = false // Requires user confirmation
		integrationResp.Decision = "ask"
		if resp.Reason != "" {
			integrationResp.Reason = fmt.Sprintf("[NinjaShield Risk: %d] %s", resp.RiskScore, resp.Reason)
		}

	default:
		integrationResp.Allowed = false
		integrationResp.Decision = "ask"
	}

	// Convert findings
	if len(resp.Findings) > 0 {
		integrationResp.Findings = make([]plugin.IntegrationFinding, len(resp.Findings))
		for i, f := range resp.Findings {
			integrationResp.Findings[i] = plugin.IntegrationFinding{
				Type:       f.Type,
				Category:   f.Category,
				Severity:   f.Severity,
				Message:    f.Message,
				Confidence: f.Confidence,
			}
		}
	}

	return integrationResp, nil
}

// HandleRequest processes a Claude Code request through the full pipeline.
func (c *ClaudeCodeIntegration) HandleRequest(ctx context.Context, raw []byte) (*plugin.IntegrationResponse, error) {
	start := time.Now()

	// Parse the request
	req, err := c.ParseRequest(ctx, raw)
	if err != nil {
		return nil, err
	}

	// Check if tool should be evaluated
	if !c.shouldEvaluateTool(req.Payload.ToolName) {
		return &plugin.IntegrationResponse{
			RequestID:        req.ID,
			Allowed:          true,
			Decision:         "allow",
			Reason:           "Tool not evaluated",
			ProcessingTimeMs: time.Since(start).Milliseconds(),
		}, nil
	}

	// Check allowed/blocked tool lists
	if c.IsToolAllowed(req.Payload.ToolName) {
		return &plugin.IntegrationResponse{
			RequestID:        req.ID,
			Allowed:          true,
			Decision:         "allow",
			Reason:           "Tool pre-approved",
			ProcessingTimeMs: time.Since(start).Milliseconds(),
		}, nil
	}

	if c.IsToolBlocked(req.Payload.ToolName) {
		return &plugin.IntegrationResponse{
			RequestID:        req.ID,
			Allowed:          false,
			Decision:         "deny",
			Reason:           "Tool is blocked by policy",
			RiskScore:        100,
			ProcessingTimeMs: time.Since(start).Milliseconds(),
		}, nil
	}

	// Get the pipeline
	pipeline := c.GetPipeline()
	if pipeline == nil {
		return nil, fmt.Errorf("no pipeline configured for Claude Code integration")
	}

	// Build pipeline request
	pipelineReq := &plugin.PipelineRequest{
		ID:          req.ID,
		Command:     req.Payload.Command,
		ContentType: req.Payload.ContentType,
		Context: plugin.PipelineContext{
			Source:           "claude-code",
			User:             req.Context.User,
			SessionID:        req.Context.SessionID,
			WorkingDirectory: req.Context.WorkingDirectory,
		},
	}

	// Set risk tolerance from config if specified
	if c.Config().RiskTolerance != "" {
		pipelineReq.RiskTolerance = plugin.RiskTolerance(c.Config().RiskTolerance)
	}

	// For file writes, evaluate the content
	if req.RequestType == "file_write" && req.Payload.FileContent != "" {
		pipelineReq.Command = req.Payload.FileContent
		pipelineReq.ContentType = "file_content"
	}

	// Evaluate through pipeline
	pipelineResp, err := pipeline.EvaluateCommand(ctx, pipelineReq)
	if err != nil {
		return nil, fmt.Errorf("pipeline evaluation failed: %w", err)
	}

	// Format response
	return c.FormatResponse(ctx, req, pipelineResp)
}

// shouldEvaluateTool checks if a tool should be evaluated.
func (c *ClaudeCodeIntegration) shouldEvaluateTool(toolName string) bool {
	for _, t := range c.evaluatedTools {
		if t == toolName || t == "*" {
			return true
		}
	}
	return false
}

// ValidateConfig validates Claude Code integration configuration.
func (c *ClaudeCodeIntegration) ValidateConfig(config map[string]any) error {
	// Validate risk_tolerance if provided
	if tolerance, ok := config["risk_tolerance"].(string); ok {
		switch tolerance {
		case "strict", "balanced", "permissive":
			// Valid
		default:
			return fmt.Errorf("invalid risk_tolerance: %s (must be strict, balanced, or permissive)", tolerance)
		}
	}

	return nil
}

// SupportedRequestTypes returns the request types this integration handles.
func (c *ClaudeCodeIntegration) SupportedRequestTypes() []string {
	return []string{"command", "file_write", "tool_call"}
}

// ToClaudeCodeOutput converts an IntegrationResponse to Claude Code output format.
func ToClaudeCodeOutput(resp *plugin.IntegrationResponse) *ClaudeCodeOutput {
	output := &ClaudeCodeOutput{
		HookSpecificOutput: HookSpecificOutput{
			HookEventName:      "PreToolUse",
			PermissionDecision: resp.Decision,
		},
	}

	if resp.Reason != "" {
		output.HookSpecificOutput.PermissionDecisionReason = resp.Reason
	}

	// Include updated input if command was modified
	if resp.ModifiedPayload != nil && resp.ModifiedPayload.Command != "" {
		output.HookSpecificOutput.UpdatedInput = map[string]any{
			"command": resp.ModifiedPayload.Command,
		}
	}

	return output
}

// MarshalClaudeCodeResponse marshals an IntegrationResponse to Claude Code JSON format.
func MarshalClaudeCodeResponse(resp *plugin.IntegrationResponse) ([]byte, error) {
	output := ToClaudeCodeOutput(resp)
	return json.Marshal(output)
}
