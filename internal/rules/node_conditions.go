package rules

import (
	"github.com/NodeVet/nodevet/internal/node"
)

// NV3001: Node must be Ready
var ruleNodeReady = NodeRule{
	ID:          "NV3001",
	Title:       "Node must be in Ready condition",
	Severity:    SeverityHigh,
	Description: "Node is not in Ready condition. Workloads may not schedule correctly and security agents may not be running.",
	Remediation: "Investigate node health: kubectl describe node <name>. Check kubelet logs and resolve underlying issues.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		status := n.Condition("Ready")
		if status != node.ConditionTrue {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  string(status),
				Message: "node is not Ready; kubelet or system components may be unhealthy",
			}
		}
		return nil
	},
}

// NV3002: Node must not have MemoryPressure
var ruleNodeMemoryPressure = NodeRule{
	ID:          "NV3002",
	Title:       "Node must not have MemoryPressure",
	Severity:    SeverityMedium,
	Description: "Node is under memory pressure. This may cause evictions and disrupt security monitoring agents.",
	Remediation: "Review memory consumption on the node. Consider scaling up or rebalancing workloads.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.Condition("MemoryPressure") == node.ConditionTrue {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "True",
				Message: "node has MemoryPressure; evictions may disrupt security agents",
			}
		}
		return nil
	},
}

// NV3003: Node must not have DiskPressure
var ruleNodeDiskPressure = NodeRule{
	ID:          "NV3003",
	Title:       "Node must not have DiskPressure",
	Severity:    SeverityMedium,
	Description: "Node is under disk pressure. Audit logs and security agent data may be lost.",
	Remediation: "Review disk usage on the node. Clean up unused images or expand disk capacity.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.Condition("DiskPressure") == node.ConditionTrue {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "True",
				Message: "node has DiskPressure; audit logs or security agent data may be lost",
			}
		}
		return nil
	},
}
