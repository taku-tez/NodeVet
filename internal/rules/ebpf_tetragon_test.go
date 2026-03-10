package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/ebpf"
)

func TestTetragonDeployed(t *testing.T) {
	rule := AllEBPFRules()[3] // NV6101

	tests := []struct {
		name    string
		info    ebpf.EBPFClusterInfo
		wantHit bool
	}{
		{
			name:    "not deployed",
			info:    ebpf.EBPFClusterInfo{},
			wantHit: true,
		},
		{
			name: "deployed, no policies",
			info: ebpf.EBPFClusterInfo{
				Tetragon: ebpf.TetragonInfo{Deployed: true},
			},
			wantHit: true,
		},
		{
			name: "deployed with policies",
			info: ebpf.EBPFClusterInfo{
				Tetragon: ebpf.TetragonInfo{Deployed: true, TracingPolicies: []string{"priv-policy"}},
			},
			wantHit: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(&tt.info)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestTetragonPrivilegedOps(t *testing.T) {
	rule := AllEBPFRules()[4] // NV6102

	tests := []struct {
		name    string
		info    ebpf.EBPFClusterInfo
		wantHit bool
	}{
		{
			name: "not deployed - skip",
			info: ebpf.EBPFClusterInfo{},
		},
		{
			name: "deployed with privileged ops policy",
			info: ebpf.EBPFClusterInfo{
				Tetragon: ebpf.TetragonInfo{
					Deployed:        true,
					TracingPolicies: []string{"priv-policy"},
					HasPrivilegedOp: true,
				},
			},
			wantHit: false,
		},
		{
			name: "deployed, no privileged ops coverage",
			info: ebpf.EBPFClusterInfo{
				Tetragon: ebpf.TetragonInfo{
					Deployed:        true,
					TracingPolicies: []string{"network-policy"},
					HasPrivilegedOp: false,
				},
			},
			wantHit: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(&tt.info)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}
