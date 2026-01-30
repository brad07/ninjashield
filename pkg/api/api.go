// Package api implements the NinjaShield HTTP API handlers.
package api

import (
	"encoding/json"
	"net/http"
)

// CommandEvaluateRequest represents a request to evaluate a command.
type CommandEvaluateRequest struct {
	Command  string `json:"command"`
	Cwd      string `json:"cwd"`
	Tool     string `json:"tool"`      // e.g., "claude_code", "codex"
	User     string `json:"user"`
	RepoRoot string `json:"repo_root"`
}

// CommandEvaluateResponse represents the response from command evaluation.
type CommandEvaluateResponse struct {
	Decision       string   `json:"decision"`
	RiskScore      int      `json:"risk_score"`
	RiskCategories []string `json:"risk_categories"`
	ReasonCodes    []string `json:"reason_codes"`
	PolicyID       string   `json:"policy_id"`
	Rewrite        *Rewrite `json:"rewrite,omitempty"`
	Context        string   `json:"context"`
}

// Rewrite represents a suggested command rewrite.
type Rewrite struct {
	Suggested string `json:"suggested"`
	Reason    string `json:"reason"`
}

// PolicyResponse represents the active policy information.
type PolicyResponse struct {
	ActivePack      string   `json:"active_pack"`
	Version         string   `json:"version"`
	RulesCount      int      `json:"rules_count"`
	ScannersEnabled []string `json:"scanners_enabled"`
	LastUpdated     string   `json:"last_updated"`
}

// ErrorResponse represents an API error.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Details string `json:"details,omitempty"`
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// WriteError writes a JSON error response.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	WriteJSON(w, status, ErrorResponse{
		Error: message,
		Code:  code,
	})
}
