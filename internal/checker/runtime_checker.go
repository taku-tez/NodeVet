package checker

import (
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/runtime"
)

// RuntimeClassChecker evaluates RuntimeClass rules.
type RuntimeClassChecker struct {
	Rules []rules.RuntimeClassRule
}

// Run evaluates all rules against the cluster runtime info.
func (c *RuntimeClassChecker) Run(info *runtime.ClusterRuntimeInfo) *rules.RuntimeClassResult {
	result := &rules.RuntimeClassResult{}
	for i := range c.Rules {
		f := c.Rules[i].Check(info)
		if f != nil {
			result.Findings = append(result.Findings, f)
			if f.Rule.Severity == rules.SeverityError {
				result.Errors++
			} else {
				result.Warnings++
			}
		} else {
			result.Passed++
		}
	}
	return result
}
