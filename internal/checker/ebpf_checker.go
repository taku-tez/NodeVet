package checker

import (
	"github.com/NodeVet/nodevet/internal/ebpf"
	"github.com/NodeVet/nodevet/internal/rules"
)

// EBPFChecker evaluates eBPF/runtime security rules.
type EBPFChecker struct {
	Rules []rules.EBPFRule
}

// Run evaluates all rules against EBPFClusterInfo.
func (c *EBPFChecker) Run(info *ebpf.EBPFClusterInfo) *rules.EBPFResult {
	result := &rules.EBPFResult{}
	for i := range c.Rules {
		f := c.Rules[i].Check(info)
		if f == nil {
			result.Passed++
		} else {
			result.Findings = append(result.Findings, f)
			if f.Rule.Severity == rules.SeverityError {
				result.Errors++
			} else {
				result.Warnings++
			}
		}
	}
	return result
}
