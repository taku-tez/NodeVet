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
	table.Header("RULE", "SEV", "SUBJECT", "DETAIL", "MESSAGE")

	isTerminal := isTerminalOutput(r.w)

	for _, f := range result.Findings {
		id := f.Rule.ID
		sev := string(f.Rule.Severity)
		msg := wrapString(f.Message, 55)
		subject := wrapString(f.Subject, 35)
		detail := wrapString(f.Detail, 30)

		if isTerminal {
			if f.Rule.Severity == rules.SeverityError {
				id = errorColor.Sprint(id)
				sev = errorColor.Sprint(sev)
			} else {
				id = warnColor.Sprint(id)
				sev = warnColor.Sprint(sev)
			}
		}

		if err := table.Append([]string{id, sev, subject, detail, msg}); err != nil {
			return fmt.Errorf("table append: %w", err)
		}
	}

	if err := table.Render(); err != nil {
		return fmt.Errorf("table render: %w", err)
	}

	summary := fmt.Sprintf("\nSummary: %d ERROR, %d WARN, %d passed\n",
		result.Errors, result.Warnings, result.Passed)
	if isTerminal {
		if result.Errors > 0 {
			summary = errorColor.Sprint(summary)
		} else if result.Warnings > 0 {
			summary = warnColor.Sprint(summary)
		} else {
			summary = passColor.Sprint(summary)
		}
	}
	_, err := fmt.Fprint(r.w, summary)
	return err
}
