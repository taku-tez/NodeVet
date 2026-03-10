package render

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

var (
	criticalColor = color.New(color.FgRed, color.Bold)
	highColor     = color.New(color.FgRed)
	mediumColor   = color.New(color.FgYellow, color.Bold)
	lowColor      = color.New(color.FgCyan)
	passColor     = color.New(color.FgGreen)
)

// TableRenderer renders findings as an ASCII table.
type TableRenderer struct {
	w io.Writer
}

func (r *TableRenderer) Render(result *checker.Result) error {
	if len(result.Findings) == 0 {
		_, err := fmt.Fprintln(r.w, passColor.Sprint("No findings. All checks passed."))
		return err
	}

	table := tablewriter.NewWriter(r.w)
	table.Header("RULE", "SEV", "MESSAGE", "ACTUAL", "REMEDIATION")

	isTerminal := isTerminalOutput(r.w)

	for _, f := range result.Findings {
		id := f.Rule.ID
		sev := string(f.Rule.Severity)
		msg := wrapString(f.Message, 50)
		actual := f.Actual
		remediation := wrapString(f.Rule.Remediation, 50)

		if isTerminal {
			id, sev = colorBySeverity(f.Rule.Severity, id, sev)
		}

		if err := table.Append([]string{id, sev, msg, actual, remediation}); err != nil {
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

// colorBySeverity applies the appropriate color to id and sev strings.
func colorBySeverity(sev rules.Severity, id, sevStr string) (string, string) {
	switch sev {
	case rules.SeverityCritical:
		return criticalColor.Sprint(id), criticalColor.Sprint(sevStr)
	case rules.SeverityHigh:
		return highColor.Sprint(id), highColor.Sprint(sevStr)
	case rules.SeverityMedium:
		return mediumColor.Sprint(id), mediumColor.Sprint(sevStr)
	default:
		return lowColor.Sprint(id), lowColor.Sprint(sevStr)
	}
}

func isTerminalOutput(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		fi, err := f.Stat()
		if err == nil && (fi.Mode()&os.ModeCharDevice) != 0 {
			return true
		}
	}
	return false
}

func wrapString(s string, width int) string {
	if len(s) <= width {
		return s
	}
	var lines []string
	for len(s) > width {
		idx := strings.LastIndex(s[:width], " ")
		if idx == -1 {
			idx = width
		}
		lines = append(lines, s[:idx])
		s = strings.TrimSpace(s[idx:])
	}
	if s != "" {
		lines = append(lines, s)
	}
	return strings.Join(lines, "\n")
}
