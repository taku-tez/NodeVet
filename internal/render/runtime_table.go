package render

import (
	"fmt"
	"io"

	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/olekukonko/tablewriter"
)

// RuntimeClassRenderer renders a RuntimeClassResult.
type RuntimeClassRenderer interface {
	RenderRuntimeClass(result *rules.RuntimeClassResult) error
}

// NewRuntimeClassRenderer returns a table renderer for RuntimeClass results.
func NewRuntimeClassRenderer(w io.Writer) RuntimeClassRenderer {
	return &runtimeClassTableRenderer{w: w}
}

type runtimeClassTableRenderer struct {
	w io.Writer
}

func (r *runtimeClassTableRenderer) RenderRuntimeClass(result *rules.RuntimeClassResult) error {
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintln(r.w, passColor.Sprint("No findings. All runtime checks passed."))
		return err
	}

	table := tablewriter.NewWriter(r.w)
	table.Header("RULE", "SEV", "MESSAGE", "ACTUAL", "REMEDIATION")

	isTerminal := isTerminalOutput(r.w)

	for _, f := range result.Findings {
		id := f.Rule.ID
		sev := string(f.Rule.Severity)
		msg := wrapString(f.Message, 50)
		remediation := wrapString(f.Rule.Remediation, 50)

		if isTerminal {
			if f.Rule.Severity == rules.SeverityError {
				id = errorColor.Sprint(id)
				sev = errorColor.Sprint(sev)
			} else {
				id = warnColor.Sprint(id)
				sev = warnColor.Sprint(sev)
			}
		}

		if err := table.Append([]string{id, sev, msg, f.Actual, remediation}); err != nil {
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
