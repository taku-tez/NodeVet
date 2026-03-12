package render

import (
	"fmt"
	"io"

	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/olekukonko/tablewriter"
)

// AuditRenderer renders an AuditPolicyResult.
type AuditRenderer interface {
	RenderAudit(result *rules.AuditPolicyResult) error
}

// NewAuditRenderer returns a table renderer for audit policy results.
func NewAuditRenderer(w io.Writer) AuditRenderer {
	return &auditTableRenderer{w: w}
}

type auditTableRenderer struct {
	w io.Writer
}

func (r *auditTableRenderer) RenderAudit(result *rules.AuditPolicyResult) error {
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintln(r.w, passColor.Sprint("No findings. AuditPolicy is complete."))
		return err
	}

	table := tablewriter.NewWriter(r.w)
	table.Header("RULE", "SEV", "GAP", "ACTUAL LEVEL", "MESSAGE", "REMEDIATION")

	isTerminal := isTerminalOutput(r.w)

	for _, f := range result.Findings {
		id := f.Rule.ID
		sev := string(f.Rule.Severity)
		msg := wrapString(f.Message, 45)
		gap := wrapString(f.Gap, 30)
		remediation := wrapString(f.Rule.Remediation, 40)

		if isTerminal {
			id, sev = colorBySeverity(f.Rule.Severity, id, sev)
		}

		if err := table.Append([]string{id, sev, gap, f.Actual, msg, remediation}); err != nil {
			return fmt.Errorf("table append: %w", err)
		}
	}

	if err := table.Render(); err != nil {
		return fmt.Errorf("table render: %w", err)
	}

	summary := fmt.Sprintf("\nSummary: %d critical/high, %d medium/low, %d passed\n",
		result.Errors, result.Warnings, result.Passed)
	if isTerminal {
		if result.Errors > 0 {
			summary = criticalColor.Sprint(summary)
		} else if result.Warnings > 0 {
			summary = mediumColor.Sprint(summary)
		} else {
			summary = passColor.Sprint(summary)
		}
	}
	_, err := fmt.Fprint(r.w, summary)
	return err
}
