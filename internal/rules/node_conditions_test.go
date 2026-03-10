package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/node"
)

func makeNodeInfo(name string, conditions []node.NodeCondition, platform node.Platform) *node.NodeInfo {
	return &node.NodeInfo{
		Name:        name,
		Labels:      map[string]string{},
		Annotations: map[string]string{},
		Conditions:  conditions,
		Platform:    platform,
	}
}

func TestNodeReady(t *testing.T) {
	rule := ruleNodeReady
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"Ready=True", makeNodeInfo("n1", []node.NodeCondition{{Type: "Ready", Status: node.ConditionTrue}}, node.PlatformUnknown), false},
		{"Ready=False", makeNodeInfo("n1", []node.NodeCondition{{Type: "Ready", Status: node.ConditionFalse}}, node.PlatformUnknown), true},
		{"Ready=Unknown", makeNodeInfo("n1", []node.NodeCondition{{Type: "Ready", Status: node.ConditionUnknown}}, node.PlatformUnknown), true},
		{"no conditions", makeNodeInfo("n1", nil, node.PlatformUnknown), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestNodeMemoryPressure(t *testing.T) {
	rule := ruleNodeMemoryPressure
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"MemoryPressure=True", makeNodeInfo("n1", []node.NodeCondition{{Type: "MemoryPressure", Status: node.ConditionTrue}}, node.PlatformUnknown), true},
		{"MemoryPressure=False", makeNodeInfo("n1", []node.NodeCondition{{Type: "MemoryPressure", Status: node.ConditionFalse}}, node.PlatformUnknown), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestNodeDiskPressure(t *testing.T) {
	rule := ruleNodeDiskPressure
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"DiskPressure=True", makeNodeInfo("n1", []node.NodeCondition{{Type: "DiskPressure", Status: node.ConditionTrue}}, node.PlatformUnknown), true},
		{"DiskPressure=False", makeNodeInfo("n1", []node.NodeCondition{{Type: "DiskPressure", Status: node.ConditionFalse}}, node.PlatformUnknown), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}
