package render

import (
	"encoding/json"
	"io"

	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/rules"
)

type jsonAccessFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Subject     string `json:"subject"`
	Detail      string `json:"detail"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

type jsonAccessOutput struct {
	Summary  jsonSummary         `json:"summary"`
	Findings []jsonAccessFinding `json:"findings"`
}

type jsonAuditFinding struct {
	RuleID             string `json:"rule_id"`
	Severity           string `json:"severity"`
	Gap                string `json:"gap"`
	ActualLevel        string `json:"actual_level"`
	Message            string `json:"message"`
	ShadowingRuleIndex int    `json:"shadowing_rule_index,omitempty"`
	Remediation        string `json:"remediation"`
}

type jsonAuditOutput struct {
	Summary  jsonSummary        `json:"summary"`
	Findings []jsonAuditFinding `json:"findings"`
}

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
		sev := string(f.Rule.Severity)
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

// WriteAccessJSON writes rules.AccessResult as JSON to w.
func WriteAccessJSON(w io.Writer, result *rules.AccessResult) error {
	out := jsonAccessOutput{
		Summary: jsonSummary{
			Errors:   result.Errors,
			Warnings: result.Warnings,
			Passed:   result.Passed,
		},
		Findings: make([]jsonAccessFinding, 0, len(result.Findings)),
	}
	for _, f := range result.Findings {
		out.Findings = append(out.Findings, jsonAccessFinding{
			RuleID:      f.Rule.ID,
			Severity:    string(f.EffectiveSeverity()),
			Subject:     f.Subject,
			Detail:      f.Detail,
			Message:     f.Message,
			Remediation: f.Rule.Remediation,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteAuditJSON writes rules.AuditPolicyResult as JSON to w.
func WriteAuditJSON(w io.Writer, result *rules.AuditPolicyResult) error {
	out := jsonAuditOutput{
		Summary: jsonSummary{
			Errors:   result.Errors,
			Warnings: result.Warnings,
			Passed:   result.Passed,
		},
		Findings: make([]jsonAuditFinding, 0, len(result.Findings)),
	}
	for _, f := range result.Findings {
		out.Findings = append(out.Findings, jsonAuditFinding{
			RuleID:             f.Rule.ID,
			Severity:           string(f.Rule.Severity),
			Gap:                f.Gap,
			ActualLevel:        f.Actual,
			Message:            f.Message,
			ShadowingRuleIndex: f.ShadowingRuleIndex,
			Remediation:        f.Rule.Remediation,
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
		sev := string(f.Rule.Severity)
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
