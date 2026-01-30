package storage

import (
	"sync"
	"time"
)

// MemoryStore implements Store using an in-memory slice.
// This is suitable for development and testing, not for production use.
type MemoryStore struct {
	mu     sync.RWMutex
	events []Event
	audits []AuditEvent
}

// NewMemoryStore creates a new in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		events: make([]Event, 0),
		audits: make([]AuditEvent, 0),
	}
}

// Save stores an event.
func (s *MemoryStore) Save(event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, *event)
	return nil
}

// RecordAudit records a command audit event.
func (s *MemoryStore) RecordAudit(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits = append(s.audits, event)
	return nil
}

// Query retrieves events matching the given criteria.
func (s *MemoryStore) Query(opts QueryOptions) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []Event

	for _, event := range s.events {
		// Apply filters
		if opts.Since != nil && event.Timestamp.Before(*opts.Since) {
			continue
		}
		if opts.Until != nil && event.Timestamp.After(*opts.Until) {
			continue
		}
		if opts.EventType != "" && event.EventType != opts.EventType {
			continue
		}
		if opts.Decision != "" && event.Decision != opts.Decision {
			continue
		}
		if opts.MinRisk > 0 && event.RiskScore < opts.MinRisk {
			continue
		}
		if opts.Tool != "" && event.Tool != opts.Tool {
			continue
		}

		results = append(results, event)
	}

	// Apply offset and limit
	if opts.Offset > 0 {
		if opts.Offset >= len(results) {
			return []Event{}, nil
		}
		results = results[opts.Offset:]
	}

	if opts.Limit > 0 && len(results) > opts.Limit {
		results = results[:opts.Limit]
	}

	return results, nil
}

// CountAuditsToday returns the number of audits recorded today.
func (s *MemoryStore) CountAuditsToday() (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	today := time.Now().Truncate(24 * time.Hour)
	var count int64

	for _, audit := range s.audits {
		if audit.Timestamp.After(today) {
			count++
		}
	}

	return count, nil
}

// GetAudits returns all audit events (for testing).
func (s *MemoryStore) GetAudits() []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]AuditEvent, len(s.audits))
	copy(result, s.audits)
	return result
}

// Clear removes all stored events (for testing).
func (s *MemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make([]Event, 0)
	s.audits = make([]AuditEvent, 0)
}

// Close closes the storage connection (no-op for memory store).
func (s *MemoryStore) Close() error {
	return nil
}
