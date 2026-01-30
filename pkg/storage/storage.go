// Package storage implements audit event storage for NinjaShield.
package storage

import (
	"time"
)

// Event represents an audit event.
type Event struct {
	ID             string    `json:"event_id"`
	Timestamp      time.Time `json:"timestamp"`
	EventType      string    `json:"event_type"` // "command" or "llm"
	User           string    `json:"user"`
	MachineID      string    `json:"machine_id"`
	Tool           string    `json:"tool"` // "claude_code", "codex", etc.
	Decision       string    `json:"decision"`
	PolicyID       string    `json:"policy_id"`
	ReasonCodes    []string  `json:"reason_codes"`
	RiskScore      int       `json:"risk_score"`
	RiskCategories []string  `json:"risk_categories"`
	ContentHash    string    `json:"content_hash"`
	Metadata       Metadata  `json:"metadata"`
}

// Metadata holds type-specific event data.
type Metadata struct {
	// Command event fields
	CommandArgv    []string `json:"command_argv,omitempty"`
	Cwd            string   `json:"cwd,omitempty"`
	RepoRoot       string   `json:"repo_root,omitempty"`
	RewriteApplied bool     `json:"rewrite_applied,omitempty"`
	RewrittenArgv  []string `json:"rewritten_argv,omitempty"`

	// LLM event fields (for future use)
	Provider           string   `json:"provider,omitempty"`
	Model              string   `json:"model,omitempty"`
	Endpoint           string   `json:"endpoint,omitempty"`
	RequestType        string   `json:"request_type,omitempty"`
	AttachmentsPresent bool     `json:"attachments_present,omitempty"`
	AttachmentTypes    []string `json:"attachment_types,omitempty"`
}

// AuditEvent represents a command audit event (simplified for server use).
type AuditEvent struct {
	Timestamp      time.Time
	Command        string
	Decision       string
	RiskScore      int
	RiskCategories []string
	PolicyID       string
	MatchedRules   []string
	Tool           string
	User           string
	Cwd            string
}

// Store defines the interface for event storage.
type Store interface {
	// Save stores an event.
	Save(event *Event) error

	// RecordAudit records a command audit event.
	RecordAudit(event AuditEvent) error

	// Query retrieves events matching the given criteria.
	Query(opts QueryOptions) ([]Event, error)

	// CountAuditsToday returns the number of audits recorded today.
	CountAuditsToday() (int64, error)

	// Close closes the storage connection.
	Close() error
}

// QueryOptions specifies criteria for querying events.
type QueryOptions struct {
	Limit      int
	Offset     int
	Since      *time.Time
	Until      *time.Time
	EventType  string
	Decision   string
	MinRisk    int
	Tool       string
}
