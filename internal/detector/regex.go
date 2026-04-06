package detector

import (
	"regexp"
)

// regexRule maps a PIIType to a compiled regex. Each match group 0 is the full value.
type regexRule struct {
	Type    PIIType
	Pattern *regexp.Regexp
}

var regexRules = []regexRule{
	{
		Type: PIITypeCreditCard,
		// Visa, MC, Amex, Discover — with optional spaces or dashes
		Pattern: regexp.MustCompile(`\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{3,4}\b`),
	},
	{
		Type: PIITypeEmail,
		Pattern: regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
	},
	{
		Type: PIITypePhoneNumber,
		// International and local formats: +90 555 123 45 67, (212) 555-1234, etc.
		Pattern: regexp.MustCompile(`(?:\+?[\d]{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{2,4}[\s\-.]?\d{0,4}\b`),
	},
	{
		Type: PIITypeIPAddress,
		// IPv4
		Pattern: regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b`),
	},
	{
		Type: PIITypeBankAccount,
		// IBAN: up to 34 alphanumeric chars, country code + check digits
		Pattern: regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b`),
	},
}

// detectWithRegex runs all regex rules against text and returns found entities.
// It deduplicates overlapping matches (longest match wins).
func detectWithRegex(text string, enabledTypes map[PIIType]bool) []PIIEntity {
	var entities []PIIEntity

	for _, rule := range regexRules {
		if enabledTypes != nil && !enabledTypes[rule.Type] {
			continue
		}
		matches := rule.Pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			value := text[loc[0]:loc[1]]
			// Basic sanity: credit cards need at least 15 digits
			if rule.Type == PIITypeCreditCard && len(extractDigits(value)) < 15 {
				continue
			}
			// Phone numbers need at least 7 digits to avoid false positives
			if rule.Type == PIITypePhoneNumber && len(extractDigits(value)) < 7 {
				continue
			}
			entities = append(entities, PIIEntity{
				Type:       rule.Type,
				Value:      value,
				Start:      loc[0],
				End:        loc[1],
				Confidence: 1.0,
			})
		}
	}

	return deduplicateEntities(entities)
}

func extractDigits(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			out = append(out, s[i])
		}
	}
	return string(out)
}

// deduplicateEntities removes overlapping spans, keeping the first occurrence.
func deduplicateEntities(entities []PIIEntity) []PIIEntity {
	result := make([]PIIEntity, 0, len(entities))
	for _, e := range entities {
		overlaps := false
		for _, r := range result {
			if e.Start < r.End && e.End > r.Start {
				overlaps = true
				break
			}
		}
		if !overlaps {
			result = append(result, e)
		}
	}
	return result
}
