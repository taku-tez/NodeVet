package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/node"
)

func makeGKENode(labels, annotations map[string]string) *node.NodeInfo {
	n := &node.NodeInfo{
		Name:        "gke-node",
		Labels:      labels,
		Annotations: annotations,
		Platform:    node.PlatformGKE,
		GKE: &node.GKENodeInfo{
			NodePool: labels["cloud.google.com/gke-nodepool"],
		},
	}
	n.GKE.IntegrityMonitoring = labels["cloud.google.com/gke-shielded-integrity-monitoring"] == "true"
	n.GKE.SecureBoot = labels["cloud.google.com/gke-secure-boot"] == "true"
	n.GKE.WorkloadIdentityEnabled = labels["iam.gke.io/gke-metadata-server-enabled"] == "true"
	n.GKE.BinaryAuthorizationAnnotation = annotations["alpha.kubernetes.io/binary-authorization"]
	return n
}

func TestGKEIntegrityMonitoring(t *testing.T) {
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"enabled", makeGKENode(map[string]string{"cloud.google.com/gke-shielded-integrity-monitoring": "true"}, map[string]string{}), false},
		{"disabled", makeGKENode(map[string]string{"cloud.google.com/gke-shielded-integrity-monitoring": "false"}, map[string]string{}), true},
		{"absent (not set)", makeGKENode(map[string]string{}, map[string]string{}), true},
		{"non-GKE node", &node.NodeInfo{Name: "plain", Labels: map[string]string{}, Annotations: map[string]string{}, Platform: node.PlatformUnknown}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ruleGKEIntegrityMonitoring.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestGKESecureBoot(t *testing.T) {
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"enabled", makeGKENode(map[string]string{"cloud.google.com/gke-secure-boot": "true"}, map[string]string{}), false},
		{"disabled", makeGKENode(map[string]string{"cloud.google.com/gke-secure-boot": "false"}, map[string]string{}), true},
		{"absent", makeGKENode(map[string]string{}, map[string]string{}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ruleGKESecureBoot.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestGKEWorkloadIdentity(t *testing.T) {
	tests := []struct {
		name    string
		node    *node.NodeInfo
		wantHit bool
	}{
		{"enabled", makeGKENode(map[string]string{"iam.gke.io/gke-metadata-server-enabled": "true"}, map[string]string{}), false},
		{"disabled", makeGKENode(map[string]string{}, map[string]string{}), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := ruleGKEWorkloadIdentity.Check(tt.node)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}
