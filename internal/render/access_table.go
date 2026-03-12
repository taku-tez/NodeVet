package render

import (
	"fmt"
	"io"

	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/olekukonko/tablewriter"
)


// AccessRenderer renders an AccessResult.
type AccessRenderer interface {
	RenderAccess(result *rules.AccessResult) error
}

// NewAccessRenderer returns a table renderer for access control results.
func NewAccessRenderer(w io.Writer) AccessRenderer {
	return &accessTableRenderer{w: w}
}

type accessTableRenderer struct {
	w io.Writer
}

func (r *accessTableRenderer) RenderAccess(result *rules.AccessResult) error {
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintln(r.w, passColor.Sprint("No findings. All access control checks passed."))
		return err
	}

	table := tablewriter.NewWriter(r.w)
	table.Header("RULE", "SEV", "SUBJECT", "DETAIL", "MESSAGE", "REMEDIATION")

	isTerminal := isTerminalOutput(r.w)

	for _, f := range result.Findings {
		id := f.Rule.ID
		eff := f.EffectiveSeverity()
		sev := string(eff)
		msg := wrapString(f.Message, 45)
		subject := wrapString(f.Subject, 30)
		detail := wrapString(f.Detail, 25)
		remediation := wrapString(f.Rule.Remediation, 40)

		if isTerminal {
			id, sev = colorBySeverity(eff, id, sev)
		}

		if err := table.Append([]string{id, sev, subject, detail, msg, remediation}); err != nil {
			return fmt.Errorf("table append: %w", err)
		}
	}

	if err := table.Render(); err != nil {
		return fmt.Errorf("table render: %w", err)
	}

	// Recount using effective severity (SeverityOverride may have escalated some findings)
	errors, warnings := 0, 0
	for _, f := range result.Findings {
		if rules.SeverityIsHighOrAbove(f.EffectiveSeverity()) {
			errors++
		} else {
			warnings++
		}
	}

	summary := fmt.Sprintf("\nSummary: %d critical/high, %d medium/low, %d passed\n",
		errors, warnings, result.Passed)
	if isTerminal {
		if errors > 0 {
			summary = criticalColor.Sprint(summary)
		} else if warnings > 0 {
			summary = mediumColor.Sprint(summary)
		} else {
			summary = passColor.Sprint(summary)
		}
	}
	_, err := fmt.Fprint(r.w, summary)
	return err
}
