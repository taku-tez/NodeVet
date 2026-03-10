package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/node"
)

func makeEKSNode(labels, annotations map[string]string) *node.NodeInfo {
	return &node.NodeInfo{
		Name:        "eks-node",
		Labels:      labels,
		Annotations: annotations,
		Platform:    node.PlatformEKS,
		EKS: &node.EKSNodeInfo{
			NodeGroup:    labels["eks.amazonaws.com/nodegroup"],
			CapacityType: labels["eks.amazonaws.com/capacityType"],
		},
	}
}

func TestEKSIMDSv2(t *testing.T) {
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"enforced (annotation absent)", makeEKSNode(map[string]string{}, map[string]string{}), false},
		{"explicitly disabled", makeEKSNode(map[string]string{}, map[string]string{"eks.amazonaws.com/imds-token-required": "false"}), true},
		{"non-EKS node", &node.NodeInfo{Name: "plain", Labels: map[string]string{}, Annotations: map[string]string{}, Platform: node.PlatformUnknown}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ruleEKSIMDSv2.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestEKSAMIAutoUpdate(t *testing.T) {
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"release-version present", makeEKSNode(map[string]string{"eks.amazonaws.com/release-version": "1.29.3-20240501"}, map[string]string{}), false},
		{"release-version absent", makeEKSNode(map[string]string{}, map[string]string{}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ruleEKSAMIAutoUpdate.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}
