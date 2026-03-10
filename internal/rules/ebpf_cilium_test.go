package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/ebpf"
)

func TestCiliumHubble(t *testing.T) {
	rule := AllEBPFRules()[5] // NV6201

	tests := []struct {
		name    string
		info    ebpf.EBPFClusterInfo
		wantHit bool
	}{
		{
			name:    "cilium not deployed - skip",
			info:    ebpf.EBPFClusterInfo{},
			wantHit: false,
		},
		{
			name: "cilium deployed, hubble disabled",
			info: ebpf.EBPFClusterInfo{
				Cilium: ebpf.CiliumInfo{Deployed: true, HubbleEnabled: false},
			},
			wantHit: true,
		},
		{
			name: "cilium deployed, hubble enabled",
			info: ebpf.EBPFClusterInfo{
				Cilium: ebpf.CiliumInfo{Deployed: true, HubbleEnabled: true},
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

func TestCiliumL7Proxy(t *testing.T) {
	rule := AllEBPFRules()[6] // NV6202

	tests := []struct {
		name    string
		info    ebpf.EBPFClusterInfo
		wantHit bool
	}{
		{
			name:    "cilium not deployed - skip",
			info:    ebpf.EBPFClusterInfo{},
			wantHit: false,
		},
		{
			name: "cilium deployed, l7 proxy disabled",
			info: ebpf.EBPFClusterInfo{
				Cilium: ebpf.CiliumInfo{Deployed: true, L7ProxyEnabled: false},
			},
			wantHit: true,
		},
		{
			name: "cilium deployed, l7 proxy enabled",
			info: ebpf.EBPFClusterInfo{
				Cilium: ebpf.CiliumInfo{Deployed: true, L7ProxyEnabled: true},
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
