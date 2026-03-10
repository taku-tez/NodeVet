package checker

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/node"
	"github.com/NodeVet/nodevet/internal/rules"
)

func TestNodeCheckerGKEInsecure(t *testing.T) {
	nodes := []*node.NodeInfo{
		{
			Name:        "gke-node-1",
			Labels:      map[string]string{"cloud.google.com/gke-nodepool": "pool-1"},
			Annotations: map[string]string{},
			Conditions:  []node.NodeCondition{{Type: "Ready", Status: node.ConditionTrue}},
			Platform:    node.PlatformGKE,
			GKE: &node.GKENodeInfo{
				NodePool:            "pool-1",
				IntegrityMonitoring: false,
				SecureBoot:          false,
				WorkloadIdentityEnabled: false,
			},
		},
	}

	c := &NodeChecker{Rules: rules.AllNodeRules()}
	result := c.RunNodes(nodes)

	// NV4001 (integrity monitoring), NV4002 (secure boot), NV4004 (workload identity) should fire
	findingIDs := make(map[string]bool)
	for _, f := range result.Findings {
		findingIDs[f.Rule.ID] = true
	}

	mustFire := []string{"NV4001", "NV4002", "NV4004"}
	for _, id := range mustFire {
		if !findingIDs[id] {
			t.Errorf("expected rule %s to fire", id)
		}
	}
}

func TestNodeCheckerPlatformFiltering(t *testing.T) {
	// Non-GKE node should not trigger GKE rules
	nodes := []*node.NodeInfo{
		{
			Name:        "plain-node",
			Labels:      map[string]string{"kubernetes.io/hostname": "plain-node"},
			Annotations: map[string]string{},
			Conditions:  []node.NodeCondition{{Type: "Ready", Status: node.ConditionTrue}},
			Platform:    node.PlatformUnknown,
		},
	}

	c := &NodeChecker{Rules: rules.AllNodeRules()}
	result := c.RunNodes(nodes)

	for _, f := range result.Findings {
		if f.Rule.Platform == node.PlatformGKE || f.Rule.Platform == node.PlatformEKS || f.Rule.Platform == node.PlatformAKS {
			t.Errorf("cloud-specific rule %s should not fire on Unknown platform node", f.Rule.ID)
		}
	}
}

func TestNodeCheckerMultipleNodes(t *testing.T) {
	nodes := []*node.NodeInfo{
		{
			Name:        "node-1",
			Labels:      map[string]string{},
			Annotations: map[string]string{},
			Conditions:  []node.NodeCondition{{Type: "Ready", Status: node.ConditionTrue}},
			Platform:    node.PlatformUnknown,
		},
		{
			Name:        "node-2",
			Labels:      map[string]string{},
			Annotations: map[string]string{},
			Conditions:  []node.NodeCondition{{Type: "Ready", Status: node.ConditionFalse}},
			Platform:    node.PlatformUnknown,
		},
	}

	c := &NodeChecker{Rules: rules.AllNodeRules()}
	result := c.RunNodes(nodes)

	// node-2 is not ready → NV3001 should fire
	found := false
	for _, f := range result.Findings {
		if f.Rule.ID == "NV3001" && f.Node == "node-2" {
			found = true
		}
	}
	if !found {
		t.Error("NV3001 should fire for node-2 which is not Ready")
	}
}
