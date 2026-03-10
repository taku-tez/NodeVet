package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/ebpf"
)

func TestFalcoDeployed(t *testing.T) {
	rule := AllEBPFRules()[0] // NV6001

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
			name:    "deployed",
			info:    ebpf.EBPFClusterInfo{Falco: ebpf.FalcoInfo{Deployed: true}},
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

func TestFalcoCriticalRulesDisabled(t *testing.T) {
	rule := AllEBPFRules()[1] // NV6002

	falseVal := false
	_ = falseVal

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
			name: "deployed, no disabled rules",
			info: ebpf.EBPFClusterInfo{
				Falco: ebpf.FalcoInfo{
					Deployed:   true,
					RulesFiles: []ebpf.FalcoRulesFile{{Name: "falco-rules/rules.yaml"}},
				},
			},
			wantHit: false,
		},
		{
			name: "deployed, critical rule disabled",
			info: ebpf.EBPFClusterInfo{
				Falco: ebpf.FalcoInfo{
					Deployed: true,
					RulesFiles: []ebpf.FalcoRulesFile{
						{Name: "falco-rules/rules.yaml", DisabledCritical: []string{"Terminal shell in container"}},
					},
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

func TestFalcoOutput(t *testing.T) {
	rule := AllEBPFRules()[2] // NV6003

	tests := []struct {
		name    string
		info    ebpf.EBPFClusterInfo
		wantHit bool
	}{
		{
			name:    "not deployed - skip",
			info:    ebpf.EBPFClusterInfo{},
			wantHit: false,
		},
		{
			name: "deployed, no webhook",
			info: ebpf.EBPFClusterInfo{
				Falco: ebpf.FalcoInfo{Deployed: true, OutputWebhook: false},
			},
			wantHit: true,
		},
		{
			name: "deployed, webhook configured",
			info: ebpf.EBPFClusterInfo{
				Falco: ebpf.FalcoInfo{Deployed: true, OutputWebhook: true},
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
