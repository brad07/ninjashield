// Package scanners implements deterministic content scanners for NinjaShield.
package scanners

// Finding represents a single scanner finding.
type Finding struct {
	Type       string  `json:"type"`        // e.g., "api_key", "email", "destructive_command"
	Category   string  `json:"category"`    // e.g., "secrets", "pii", "dangerous_command"
	Severity   string  `json:"severity"`    // "low", "medium", "high", "critical"
	Confidence float64 `json:"confidence"`  // 0.0 to 1.0
	Message    string  `json:"message"`     // Human-readable description
	Location   *Location `json:"location,omitempty"` // Where in the input the finding was detected
}

// Location represents where a finding was detected.
type Location struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Scanner is the interface that all scanners must implement.
type Scanner interface {
	// Name returns the scanner's name.
	Name() string

	// Scan analyzes the input and returns findings.
	Scan(input string) []Finding
}

// ScanResult holds the combined results from all scanners.
type ScanResult struct {
	Findings      []Finding `json:"findings"`
	RiskScore     int       `json:"risk_score"`
	RiskCategories []string `json:"risk_categories"`
}

// Aggregate combines findings from multiple scanners and calculates overall risk.
func Aggregate(findings []Finding) ScanResult {
	result := ScanResult{
		Findings:       findings,
		RiskCategories: make([]string, 0),
	}

	categorySet := make(map[string]bool)
	maxScore := 0

	for _, f := range findings {
		// Track unique categories
		if !categorySet[f.Category] {
			categorySet[f.Category] = true
			result.RiskCategories = append(result.RiskCategories, f.Category)
		}

		// Calculate risk score based on severity
		score := severityToScore(f.Severity)
		if score > maxScore {
			maxScore = score
		}
	}

	result.RiskScore = maxScore
	return result
}

func severityToScore(severity string) int {
	switch severity {
	case "critical":
		return 100
	case "high":
		return 75
	case "medium":
		return 50
	case "low":
		return 25
	default:
		return 0
	}
}
