package scanners

import (
	"testing"
)

func TestPIIScanner_Name(t *testing.T) {
	s := NewPIIScanner()
	if s.Name() != "pii" {
		t.Errorf("Name() = %v, want pii", s.Name())
	}
}

func TestPIIScanner_Emails(t *testing.T) {
	s := NewPIIScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "simple email",
			input:   "contact me at john.doe@company.com",
			wantHit: true,
		},
		{
			name:    "email with plus",
			input:   "user+tag@example.org",
			wantHit: true,
		},
		{
			name:    "email with subdomain",
			input:   "admin@mail.subdomain.example.co.uk",
			wantHit: true,
		},
		{
			name:    "not an email",
			input:   "this is just text",
			wantHit: false,
		},
		{
			name:    "example.com (false positive filter)",
			input:   "user@example.com",
			wantHit: false, // Should be filtered as common false positive
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Type == "email" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found email = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestPIIScanner_PhoneNumbers(t *testing.T) {
	s := NewPIIScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "US phone with dashes",
			input:   "Call me at 555-234-5678", // Exchange must start with 2-9
			wantHit: true,
		},
		{
			name:    "US phone with dots",
			input:   "Phone: 555.234.5678",
			wantHit: true,
		},
		{
			name:    "US phone with parens",
			input:   "(555) 234-5678",
			wantHit: true,
		},
		{
			name:    "US phone with country code",
			input:   "+1-555-234-5678",
			wantHit: true,
		},
		{
			name:    "International E.164",
			input:   "+442071234567",
			wantHit: true,
		},
		{
			name:    "Not a phone number",
			input:   "123-45-6789", // This is SSN format
			wantHit: false,
		},
		{
			name:    "Invalid area code",
			input:   "123-456-7890", // Area code can't start with 1
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Type == "phone_us" || f.Type == "phone_intl" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found phone = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestPIIScanner_SSN(t *testing.T) {
	s := NewPIIScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "SSN with dashes",
			input:   "SSN: 123-45-6789",
			wantHit: true,
		},
		{
			name:    "SSN with spaces",
			input:   "123 45 6789",
			wantHit: true,
		},
		{
			name:    "SSN no separators",
			input:   "SSN is 123456789",
			wantHit: true,
		},
		{
			name:    "Invalid SSN - area 000",
			input:   "000-12-3456",
			wantHit: false,
		},
		{
			name:    "Invalid SSN - area 666",
			input:   "666-12-3456",
			wantHit: false,
		},
		{
			name:    "Invalid SSN - area 900+",
			input:   "900-12-3456",
			wantHit: false,
		},
		{
			name:    "Invalid SSN - group 00",
			input:   "123-00-4567",
			wantHit: false,
		},
		{
			name:    "Invalid SSN - serial 0000",
			input:   "123-45-0000",
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Type == "ssn" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found SSN = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestPIIScanner_CreditCards(t *testing.T) {
	s := NewPIIScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
		cardType string
	}{
		{
			name:     "Visa",
			input:    "4111-1111-1111-1111",
			wantHit:  true,
			cardType: "credit_card_visa",
		},
		{
			name:     "Visa no dashes",
			input:    "4111111111111111",
			wantHit:  true,
			cardType: "credit_card_visa",
		},
		{
			name:     "Mastercard",
			input:    "5500-0000-0000-0004",
			wantHit:  true,
			cardType: "credit_card_mastercard",
		},
		{
			name:     "American Express",
			input:    "3400-000000-00009",
			wantHit:  true,
			cardType: "credit_card_amex",
		},
		{
			name:     "Discover",
			input:    "6011-0000-0000-0004",
			wantHit:  true,
			cardType: "credit_card_discover",
		},
		{
			name:    "Invalid Luhn",
			input:   "4111-1111-1111-1112", // Fails Luhn check
			wantHit: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if tt.cardType != "" && f.Type == tt.cardType {
					found = true
					break
				} else if tt.cardType == "" && f.Category == "pii" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found credit card = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestPIIScanner_IPAddresses(t *testing.T) {
	s := NewPIIScanner()

	tests := []struct {
		name    string
		input   string
		wantHit bool
	}{
		{
			name:    "Public IPv4",
			input:   "Server IP: 8.8.8.8",
			wantHit: true,
		},
		{
			name:    "Another public IPv4",
			input:   "Connect to 203.0.113.50",
			wantHit: true,
		},
		{
			name:    "Localhost (filtered)",
			input:   "127.0.0.1",
			wantHit: false,
		},
		{
			name:    "Private 10.x (filtered)",
			input:   "10.0.0.1",
			wantHit: false,
		},
		{
			name:    "Private 192.168.x (filtered)",
			input:   "192.168.1.1",
			wantHit: false,
		},
		{
			name:    "IPv6",
			input:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			wantHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := s.Scan(tt.input)
			found := false
			for _, f := range findings {
				if f.Type == "ipv4" || f.Type == "ipv6" {
					found = true
					break
				}
			}
			if found != tt.wantHit {
				t.Errorf("Scan() found IP = %v, want %v", found, tt.wantHit)
			}
		})
	}
}

func TestPIIScanner_Config(t *testing.T) {
	// Test with custom config that disables some detections
	config := PIIConfig{
		DetectEmails:      false,
		DetectPhones:      true,
		DetectSSN:         false,
		DetectCreditCards: false,
		DetectIPAddresses: false,
		DetectAddresses:   false,
	}

	s := NewPIIScannerWithConfig(config)

	input := "Email: test@example.com, Phone: 555-234-5678, SSN: 123-45-6789"
	findings := s.Scan(input)

	// Should only find phone
	foundEmail := false
	foundPhone := false
	foundSSN := false

	for _, f := range findings {
		switch f.Type {
		case "email":
			foundEmail = true
		case "phone_us", "phone_intl":
			foundPhone = true
		case "ssn":
			foundSSN = true
		}
	}

	if foundEmail {
		t.Error("Should not detect email when disabled")
	}
	if !foundPhone {
		t.Error("Should detect phone when enabled")
	}
	if foundSSN {
		t.Error("Should not detect SSN when disabled")
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		{"4111111111111111", true},  // Valid Visa test number
		{"5500000000000004", true},  // Valid Mastercard test number
		{"340000000000009", true},   // Valid Amex test number
		{"6011000000000004", true},  // Valid Discover test number
		{"4111111111111112", false}, // Invalid
		{"1234567890123456", false}, // Invalid
		{"", false},                  // Empty
		{"123", false},               // Too short
	}

	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			got := luhnCheck(tt.number)
			if got != tt.valid {
				t.Errorf("luhnCheck(%s) = %v, want %v", tt.number, got, tt.valid)
			}
		})
	}
}

func TestRedactPII(t *testing.T) {
	tests := []struct {
		input   string
		piiType string
		want    string
	}{
		{"john.doe@company.com", "email", "jo***@company.com"},
		{"555-123-4567", "phone", "***-***-4567"},
		{"123-45-6789", "ssn", "***-**-****"},
		{"4111111111111111", "credit_card", "****-****-****-1111"},
		{"8.8.8.8", "ip_address", "8.***.***.***"},
	}

	for _, tt := range tests {
		t.Run(tt.piiType, func(t *testing.T) {
			got := RedactPII(tt.input, tt.piiType)
			if got != tt.want {
				t.Errorf("RedactPII(%s, %s) = %s, want %s", tt.input, tt.piiType, got, tt.want)
			}
		})
	}
}

func TestPIIScanner_NoFalsePositives(t *testing.T) {
	s := NewPIIScanner()

	// These should NOT trigger high-confidence PII detection
	inputs := []string{
		"Hello world",
		"The year is 2024",
		"Version 1.2.3.4",      // Not an IP
		"Order #12345678901234", // Not a credit card (no Luhn)
	}

	for _, input := range inputs {
		t.Run(input[:min(20, len(input))], func(t *testing.T) {
			findings := s.Scan(input)
			highConfidence := 0
			for _, f := range findings {
				if f.Confidence >= 0.8 {
					highConfidence++
				}
			}
			if highConfidence > 0 {
				t.Errorf("False positive in: %s, findings: %v", input, findings)
			}
		})
	}
}
