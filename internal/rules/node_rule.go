package rules

import "github.com/NodeVet/nodevet/internal/node"

// NodeRule describes a security check that operates on a live Node.
type NodeRule struct {
	ID          string
	Title       string
	Severity    Severity
	Description string
	Remediation string
	// Platform limits this rule to a specific cloud provider.
	// If empty, the rule applies to all platforms.
	Platform node.Platform
	Check    func(n *node.NodeInfo) *NodeFinding
}

// NodeFinding is produced when a NodeRule detects a problem.
type NodeFinding struct {
	Rule             *NodeRule
	Node             string
	Actual           string
	Message          string
	SeverityOverride *Severity // when set, overrides Rule.Severity for display and counting
}

// EffectiveSeverity returns the override severity if set, otherwise the rule's severity.
func (f *NodeFinding) EffectiveSeverity() Severity {
	if f.SeverityOverride != nil {
		return *f.SeverityOverride
	}
	return f.Rule.Severity
}

// NodeResult holds findings for a set of nodes.
type NodeResult struct {
	Findings []*NodeFinding
	Passed   int
	Errors   int
	Warnings int
}
