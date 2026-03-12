package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/NodeVet/nodevet/internal/correlate"
	"github.com/olekukonko/tablewriter"
)

// RenderCorrelations prints compound attack-path findings to w.
func RenderCorrelations(w io.Writer, findings []correlate.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	fmt.Fprintln(w, "\n=== Attack Path Correlations ===")

	table := tablewriter.NewWriter(w)
	table.Header("ID", "SEV", "RULES", "MESSAGE", "REMEDIATION")

	isTerminal := isTerminalOutput(w)

	for _, f := range findings {
		id := f.ID
		sev := string(f.Severity)
		ruleIDs := strings.Join(f.RuleIDs, " + ")
		msg := wrapString(f.Message, 50)
		remediation := wrapString(f.Remediation, 40)

		if isTerminal {
			id, sev = colorBySeverity(f.Severity, id, sev)
		}

		if err := table.Append([]string{id, sev, ruleIDs, msg, remediation}); err != nil {
			return fmt.Errorf("table append: %w", err)
		}
	}

	return table.Render()
}
