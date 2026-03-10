package checker

import (
	"github.com/NodeVet/nodevet/internal/audit"
	"github.com/NodeVet/nodevet/internal/rules"
)

// AuditPolicyChecker evaluates AuditPolicy completeness rules.
type AuditPolicyChecker struct {
	Rules []rules.AuditPolicyRule
}

// Run evaluates all rules against the parsed AuditPolicy.
func (c *AuditPolicyChecker) Run(policy *audit.Policy) *rules.AuditPolicyResult {
	result := &rules.AuditPolicyResult{}
	for i := range c.Rules {
		f := c.Rules[i].Check(policy)
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
