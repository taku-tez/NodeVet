package render

import (
	"fmt"
	"io"

	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/olekukonko/tablewriter"
)

// EBPFRenderer renders an EBPFResult.
type EBPFRenderer interface {
	RenderEBPF(result *rules.EBPFResult) error
}

// NewEBPFRenderer returns a table renderer for eBPF/runtime security results.
func NewEBPFRenderer(w io.Writer) EBPFRenderer {
	return &ebpfTableRenderer{w: w}
}

type ebpfTableRenderer struct {
	w io.Writer
}

func (r *ebpfTableRenderer) RenderEBPF(result *rules.EBPFResult) error {
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintln(r.w, passColor.Sprint("No findings. eBPF/runtime security checks passed."))
		return err
	}

	table := tablewriter.NewWriter(r.w)
	table.Header("RULE", "SEV", "ACTUAL", "MESSAGE", "REMEDIATION")

	isTerminal := isTerminalOutput(r.w)

	for _, f := range result.Findings {
		id := f.Rule.ID
		sev := string(f.Rule.Severity)
		actual := wrapString(f.Actual, 25)
		msg := wrapString(f.Message, 50)
		remediation := wrapString(f.Rule.Remediation, 40)

		if isTerminal {
			id, sev = colorBySeverity(f.Rule.Severity, id, sev)
		}

		if err := table.Append([]string{id, sev, actual, msg, remediation}); err != nil {
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
