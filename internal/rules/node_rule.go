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
	Rule    *NodeRule
	Node    string
	Actual  string
	Message string
}

// NodeResult holds findings for a set of nodes.
type NodeResult struct {
	Findings []*NodeFinding
	Passed   int
	Errors   int
	Warnings int
}
