package render

import (
	"fmt"
	"io"

	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/olekukonko/tablewriter"
)

// NodeRenderer renders a NodeResult.
type NodeRenderer interface {
	RenderNodes(result *rules.NodeResult) error
}

// NewNodeRenderer returns a table renderer for node results.
func NewNodeRenderer(w io.Writer) NodeRenderer {
	return &nodeTableRenderer{w: w}
}

type nodeTableRenderer struct {
	w io.Writer
}

func (r *nodeTableRenderer) RenderNodes(result *rules.NodeResult) error {
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintln(r.w, passColor.Sprint("No findings. All node checks passed."))
		return err
	}

	table := tablewriter.NewWriter(r.w)
	table.Header("RULE", "SEV", "NODE", "MESSAGE", "ACTUAL", "REMEDIATION")

	isTerminal := isTerminalOutput(r.w)

	for _, f := range result.Findings {
		id := f.Rule.ID
		sev := string(f.Rule.Severity)
		msg := wrapString(f.Message, 45)
		remediation := wrapString(f.Rule.Remediation, 45)

		if isTerminal {
			id, sev = colorBySeverity(f.Rule.Severity, id, sev)
		}

		if err := table.Append([]string{id, sev, f.Node, msg, f.Actual, remediation}); err != nil {
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
