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
	errorColor = color.New(color.FgRed, color.Bold)
	warnColor  = color.New(color.FgYellow, color.Bold)
	passColor  = color.New(color.FgGreen)
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
			if f.Rule.Severity == rules.SeverityError {
				id = errorColor.Sprint(id)
				sev = errorColor.Sprint(sev)
			} else {
				id = warnColor.Sprint(id)
				sev = warnColor.Sprint(sev)
			}
		}

		if err := table.Append([]string{id, sev, msg, actual, remediation}); err != nil {
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
