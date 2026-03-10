package checker

import (
	"fmt"

	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/source"
)

// Checker orchestrates sources and rules to produce a Result.
type Checker struct {
	Sources []source.ConfigSource
	Rules   []rules.Rule
}

// Result holds all findings and summary counts.
type Result struct {
	Findings []*rules.Finding
	Passed   int
	Errors   int
	Warnings int
}

// Run loads all sources, merges them, and evaluates all rules.
func (c *Checker) Run() (*Result, error) {
	var maps []map[string]string
	for _, src := range c.Sources {
		m, err := src.Load()
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", src.SourceName(), err)
		}
		maps = append(maps, m)
	}

	merged := source.Merge(maps...)

	result := &Result{}
	for i := range c.Rules {
		f := c.Rules[i].Check(merged)
		if f != nil {
			result.Findings = append(result.Findings, f)
			if rules.SeverityIsHighOrAbove(f.Rule.Severity) {
				result.Errors++
			} else {
				result.Warnings++
			}
		} else {
			result.Passed++
		}
	}
	return result, nil
}
