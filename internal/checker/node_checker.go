package checker

import (
	"github.com/NodeVet/nodevet/internal/node"
	"github.com/NodeVet/nodevet/internal/rules"
)

// NodeChecker evaluates node-level rules against a set of nodes.
type NodeChecker struct {
	Rules []rules.NodeRule
}

// RunNodes evaluates all rules against each node.
func (c *NodeChecker) RunNodes(nodes []*node.NodeInfo) *rules.NodeResult {
	result := &rules.NodeResult{}
	for _, n := range nodes {
		for i := range c.Rules {
			r := &c.Rules[i]
			// Skip platform-specific rules for non-matching nodes.
			if r.Platform != "" && r.Platform != n.Platform {
				result.Passed++
				continue
			}
			f := r.Check(n)
			if f != nil {
				result.Findings = append(result.Findings, f)
				if r.Severity == rules.SeverityError {
					result.Errors++
				} else {
					result.Warnings++
				}
			} else {
				result.Passed++
			}
		}
	}
	return result
}
