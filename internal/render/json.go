package render

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/rules"
)

type jsonFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	Actual      string `json:"actual,omitempty"`
	Remediation string `json:"remediation"`
}

type jsonNodeFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Node        string `json:"node"`
	Message     string `json:"message"`
	Actual      string `json:"actual,omitempty"`
	Remediation string `json:"remediation"`
}

type jsonSummary struct {
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Passed   int `json:"passed"`
}

type jsonOutput struct {
	Summary  jsonSummary   `json:"summary"`
	Findings []jsonFinding `json:"findings"`
}

type jsonNodeOutput struct {
	Summary  jsonSummary       `json:"summary"`
	Findings []jsonNodeFinding `json:"findings"`
}

// WriteCheckerJSON writes checker.Result as JSON to w.
func WriteCheckerJSON(w io.Writer, result *checker.Result) error {
	out := jsonOutput{
		Summary: jsonSummary{
			Errors:   result.Errors,
			Warnings: result.Warnings,
			Passed:   result.Passed,
		},
		Findings: make([]jsonFinding, 0, len(result.Findings)),
	}
	for _, f := range result.Findings {
		sev := strings.ToLower(string(f.Rule.Severity))
		out.Findings = append(out.Findings, jsonFinding{
			RuleID:      f.Rule.ID,
			Severity:    sev,
			Message:     f.Message,
			Actual:      f.Actual,
			Remediation: f.Rule.Remediation,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteNodeJSON writes rules.NodeResult as JSON to w.
func WriteNodeJSON(w io.Writer, result *rules.NodeResult) error {
	out := jsonNodeOutput{
		Summary: jsonSummary{
			Errors:   result.Errors,
			Warnings: result.Warnings,
			Passed:   result.Passed,
		},
		Findings: make([]jsonNodeFinding, 0, len(result.Findings)),
	}
	for _, f := range result.Findings {
		sev := strings.ToLower(string(f.Rule.Severity))
		out.Findings = append(out.Findings, jsonNodeFinding{
			RuleID:      f.Rule.ID,
			Severity:    sev,
			Node:        f.Node,
			Message:     f.Message,
			Actual:      f.Actual,
			Remediation: f.Rule.Remediation,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
