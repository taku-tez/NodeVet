package checker

import (
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/access"
)

// AccessChecker evaluates access control rules.
type AccessChecker struct {
	Rules []rules.AccessRule
}

// Run evaluates all rules against ClusterAccessInfo.
func (c *AccessChecker) Run(info *access.ClusterAccessInfo) *rules.AccessResult {
	result := &rules.AccessResult{}
	for i := range c.Rules {
		findings := c.Rules[i].Check(info)
		if len(findings) == 0 {
			result.Passed++
		} else {
			for _, f := range findings {
				result.Findings = append(result.Findings, f)
				if rules.SeverityIsHighOrAbove(f.Rule.Severity) {
					result.Errors++
				} else {
					result.Warnings++
				}
			}
		}
	}
	return result
}
