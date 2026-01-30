package scanners

import (
	"regexp"
	"strconv"
	"strings"
)

// PIIScanner detects personally identifiable information.
type PIIScanner struct {
	patterns []piiPattern
	config   PIIConfig
}

// PIIConfig allows customizing which PII types to detect.
type PIIConfig struct {
	DetectEmails      bool
	DetectPhones      bool
	DetectSSN         bool
	DetectCreditCards bool
	DetectIPAddresses bool
	DetectAddresses   bool
}

// DefaultPIIConfig returns the default PII detection configuration.
func DefaultPIIConfig() PIIConfig {
	return PIIConfig{
		DetectEmails:      true,
		DetectPhones:      true,
		DetectSSN:         true,
		DetectCreditCards: true,
		DetectIPAddresses: true,
		DetectAddresses:   false, // Address detection has more false positives
	}
}

type piiPattern struct {
	name       string
	piiType    string
	regex      *regexp.Regexp
	severity   string
	confidence float64
	message    string
	validator  func(string) bool // Optional validation function
}

// NewPIIScanner creates a new PII scanner with default configuration.
func NewPIIScanner() *PIIScanner {
	return NewPIIScannerWithConfig(DefaultPIIConfig())
}

// NewPIIScannerWithConfig creates a new PII scanner with custom configuration.
func NewPIIScannerWithConfig(config PIIConfig) *PIIScanner {
	return &PIIScanner{
		patterns: buildPIIPatterns(config),
		config:   config,
	}
}

func buildPIIPatterns(config PIIConfig) []piiPattern {
	var patterns []piiPattern

	if config.DetectEmails {
		patterns = append(patterns, piiPattern{
			name:       "email",
			piiType:    "email",
			regex:      regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			severity:   "medium",
			confidence: 0.90,
			message:    "Email address detected",
			validator:  isValidEmail,
		})
	}

	if config.DetectPhones {
		// US phone numbers
		patterns = append(patterns, piiPattern{
			name:       "phone_us",
			piiType:    "phone",
			regex:      regexp.MustCompile(`\b(?:\+?1[-.\s]?)?\(?[2-9][0-9]{2}\)?[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b`),
			severity:   "medium",
			confidence: 0.75,
			message:    "US phone number detected",
			validator:  isValidUSPhone,
		})

		// International phone numbers (E.164 format)
		patterns = append(patterns, piiPattern{
			name:       "phone_intl",
			piiType:    "phone",
			regex:      regexp.MustCompile(`(?:^|[^0-9])\+([1-9][0-9]{6,14})(?:[^0-9]|$)`),
			severity:   "medium",
			confidence: 0.80,
			message:    "International phone number detected",
		})
	}

	if config.DetectSSN {
		patterns = append(patterns, piiPattern{
			name:       "ssn",
			piiType:    "ssn",
			regex:      regexp.MustCompile(`\b[0-9]{3}[-\s]?[0-9]{2}[-\s]?[0-9]{4}\b`),
			severity:   "critical",
			confidence: 0.70,
			message:    "Social Security Number detected",
			validator:  isValidSSN,
		})
	}

	if config.DetectCreditCards {
		// Visa
		patterns = append(patterns, piiPattern{
			name:       "credit_card_visa",
			piiType:    "credit_card",
			regex:      regexp.MustCompile(`\b4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b`),
			severity:   "critical",
			confidence: 0.85,
			message:    "Visa credit card number detected",
			validator:  isValidCreditCard,
		})

		// Mastercard
		patterns = append(patterns, piiPattern{
			name:       "credit_card_mastercard",
			piiType:    "credit_card",
			regex:      regexp.MustCompile(`\b5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b`),
			severity:   "critical",
			confidence: 0.85,
			message:    "Mastercard credit card number detected",
			validator:  isValidCreditCard,
		})

		// American Express
		patterns = append(patterns, piiPattern{
			name:       "credit_card_amex",
			piiType:    "credit_card",
			regex:      regexp.MustCompile(`\b3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}\b`),
			severity:   "critical",
			confidence: 0.85,
			message:    "American Express credit card number detected",
			validator:  isValidCreditCard,
		})

		// Discover
		patterns = append(patterns, piiPattern{
			name:       "credit_card_discover",
			piiType:    "credit_card",
			regex:      regexp.MustCompile(`\b6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}\b`),
			severity:   "critical",
			confidence: 0.85,
			message:    "Discover credit card number detected",
			validator:  isValidCreditCard,
		})
	}

	if config.DetectIPAddresses {
		// IPv4
		patterns = append(patterns, piiPattern{
			name:       "ipv4",
			piiType:    "ip_address",
			regex:      regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			severity:   "low",
			confidence: 0.90,
			message:    "IPv4 address detected",
			validator:  isNotLocalIP,
		})

		// IPv6 (simplified pattern)
		patterns = append(patterns, piiPattern{
			name:       "ipv6",
			piiType:    "ip_address",
			regex:      regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			severity:   "low",
			confidence: 0.85,
			message:    "IPv6 address detected",
		})
	}

	if config.DetectAddresses {
		// US street addresses (simplified pattern)
		patterns = append(patterns, piiPattern{
			name:       "address_us",
			piiType:    "address",
			regex:      regexp.MustCompile(`\b\d{1,5}\s+(?:[A-Za-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\.?\b`),
			severity:   "medium",
			confidence: 0.60,
			message:    "Street address detected",
		})

		// US ZIP codes
		patterns = append(patterns, piiPattern{
			name:       "zipcode_us",
			piiType:    "address",
			regex:      regexp.MustCompile(`\b[0-9]{5}(?:-[0-9]{4})?\b`),
			severity:   "low",
			confidence: 0.50,
			message:    "US ZIP code detected",
		})
	}

	return patterns
}

// Name returns the scanner name.
func (s *PIIScanner) Name() string {
	return "pii"
}

// Scan analyzes the input for PII.
func (s *PIIScanner) Scan(input string) []Finding {
	var findings []Finding

	for _, pattern := range s.patterns {
		matches := pattern.regex.FindAllStringIndex(input, -1)
		for _, match := range matches {
			matchedText := input[match[0]:match[1]]

			// Run validator if present
			if pattern.validator != nil && !pattern.validator(matchedText) {
				continue
			}

			findings = append(findings, Finding{
				Type:       pattern.name,
				Category:   "pii",
				Severity:   pattern.severity,
				Confidence: pattern.confidence,
				Message:    pattern.message,
				Location: &Location{
					Start: match[0],
					End:   match[1],
				},
			})
		}
	}

	return findings
}

// Validation functions

func isValidEmail(s string) bool {
	// Basic validation - already matched by regex
	// Additional checks: not a common false positive
	lower := strings.ToLower(s)
	falsePositives := []string{
		"example.com", "test.com", "localhost",
		"email@example", "user@domain",
	}
	for _, fp := range falsePositives {
		if strings.Contains(lower, fp) {
			return false
		}
	}
	return true
}

func isValidUSPhone(s string) bool {
	// Remove non-digits
	digits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(s, "")

	// Should be 10 or 11 digits (with country code)
	if len(digits) < 10 || len(digits) > 11 {
		return false
	}

	// Area code shouldn't start with 0 or 1
	areaCode := digits
	if len(digits) == 11 {
		areaCode = digits[1:]
	}
	if areaCode[0] == '0' || areaCode[0] == '1' {
		return false
	}

	return true
}

func isValidSSN(s string) bool {
	// Remove non-digits
	digits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(s, "")

	if len(digits) != 9 {
		return false
	}

	// SSN validation rules
	area, _ := strconv.Atoi(digits[0:3])
	group, _ := strconv.Atoi(digits[3:5])
	serial, _ := strconv.Atoi(digits[5:9])

	// Area number cannot be 000, 666, or 900-999
	if area == 0 || area == 666 || (area >= 900 && area <= 999) {
		return false
	}

	// Group number cannot be 00
	if group == 0 {
		return false
	}

	// Serial number cannot be 0000
	if serial == 0 {
		return false
	}

	return true
}

func isValidCreditCard(s string) bool {
	// Remove non-digits
	digits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(s, "")

	// Luhn algorithm validation
	return luhnCheck(digits)
}

func luhnCheck(number string) bool {
	if len(number) < 13 || len(number) > 19 {
		return false
	}

	sum := 0
	isSecond := false

	for i := len(number) - 1; i >= 0; i-- {
		d, err := strconv.Atoi(string(number[i]))
		if err != nil {
			return false
		}

		if isSecond {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}

		sum += d
		isSecond = !isSecond
	}

	return sum%10 == 0
}

func isNotLocalIP(s string) bool {
	// Filter out common local/private IPs
	localPrefixes := []string{
		"127.", "10.", "192.168.", "172.16.", "172.17.",
		"172.18.", "172.19.", "172.20.", "172.21.", "172.22.",
		"172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"0.0.0.0", "255.255.255.255",
	}

	for _, prefix := range localPrefixes {
		if strings.HasPrefix(s, prefix) {
			return false
		}
	}

	// Filter out version-number-like patterns (small sequential numbers like 1.2.3.4)
	parts := strings.Split(s, ".")
	if len(parts) == 4 {
		nums := make([]int, 4)
		allSmall := true
		for i, part := range parts {
			n, err := strconv.Atoi(part)
			if err != nil {
				allSmall = false
				break
			}
			nums[i] = n
			if n >= 10 {
				allSmall = false
			}
		}
		// Only filter if all small AND looks like a version (not all same, generally ascending)
		if allSmall && (nums[0] != nums[1] || nums[1] != nums[2] || nums[2] != nums[3]) {
			// Check if roughly ascending like 1.2.3.4
			if nums[0] <= nums[1] && nums[1] <= nums[2] && nums[2] <= nums[3] {
				return false // Likely a version number like 1.2.3.4
			}
		}
	}

	return true
}

// RedactPII redacts PII data based on type.
func RedactPII(s string, piiType string) string {
	switch piiType {
	case "email":
		parts := strings.Split(s, "@")
		if len(parts) == 2 {
			local := parts[0]
			if len(local) > 2 {
				return local[:2] + "***@" + parts[1]
			}
			return "***@" + parts[1]
		}
		return "***@***"

	case "phone":
		digits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(s, "")
		if len(digits) >= 4 {
			return "***-***-" + digits[len(digits)-4:]
		}
		return "***-***-****"

	case "ssn":
		return "***-**-****"

	case "credit_card":
		digits := regexp.MustCompile(`[^0-9]`).ReplaceAllString(s, "")
		if len(digits) >= 4 {
			return "****-****-****-" + digits[len(digits)-4:]
		}
		return "****-****-****-****"

	case "ip_address":
		parts := strings.Split(s, ".")
		if len(parts) == 4 {
			return parts[0] + ".***.***.***"
		}
		return "***.***.***.***"

	default:
		return strings.Repeat("*", len(s))
	}
}
