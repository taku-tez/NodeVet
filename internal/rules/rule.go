package rules

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// SeverityIsHighOrAbove returns true for CRITICAL and HIGH severities,
// used to classify findings as errors vs warnings in summaries.
func SeverityIsHighOrAbove(s Severity) bool {
	return s == SeverityCritical || s == SeverityHigh
}

// Rule describes a single security check.
type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	Description string
	Remediation string
	Check       func(values map[string]string) *Finding
}

// Finding is produced when a Rule's Check detects a problem.
type Finding struct {
	Rule    *Rule
	Actual  string
	Message string
}

// boolVal returns the boolean value for a key with a given default.
func boolVal(values map[string]string, key string, defaultVal bool) bool {
	v, ok := values[key]
	if !ok {
		return defaultVal
	}
	switch v {
	case "true", "True", "TRUE", "1", "yes":
		return true
	case "false", "False", "FALSE", "0", "no":
		return false
	default:
		return defaultVal
	}
}

// stringVal returns the string value for a key.
func stringVal(values map[string]string, key string) string {
	return values[key]
}
