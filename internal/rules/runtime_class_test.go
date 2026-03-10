package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/runtime"
)

func TestRuntimeClassSandboxed(t *testing.T) {
	rule := ruleRuntimeClassSandboxed
	tests := []struct {
		name    string
		info    *runtime.ClusterRuntimeInfo
		wantHit bool
	}{
		{
			name:    "no runtimeclasses",
			info:    &runtime.ClusterRuntimeInfo{},
			wantHit: true,
		},
		{
			name: "only runc (no sandbox)",
			info: &runtime.ClusterRuntimeInfo{
				RuntimeClasses: []runtime.RuntimeClassInfo{{Name: "default", Handler: "runc"}},
			},
			wantHit: true,
		},
		{
			name: "gVisor present",
			info: &runtime.ClusterRuntimeInfo{
				RuntimeClasses: []runtime.RuntimeClassInfo{
					{Name: "default", Handler: "runc"},
					{Name: "gvisor", Handler: "runsc"},
				},
			},
			wantHit: false,
		},
		{
			name: "Kata present",
			info: &runtime.ClusterRuntimeInfo{
				RuntimeClasses: []runtime.RuntimeClassInfo{
					{Name: "kata", Handler: "kata"},
				},
			},
			wantHit: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.info)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestRuntimeClassHandlerValid(t *testing.T) {
	rule := ruleRuntimeClassHandlerValid
	tests := []struct {
		name    string
		info    *runtime.ClusterRuntimeInfo
		wantHit bool
	}{
		{"no runtimeclasses", &runtime.ClusterRuntimeInfo{}, false},
		{
			name: "all handlers set",
			info: &runtime.ClusterRuntimeInfo{
				RuntimeClasses: []runtime.RuntimeClassInfo{
					{Name: "runc", Handler: "runc"},
					{Name: "gvisor", Handler: "runsc"},
				},
			},
			wantHit: false,
		},
		{
			name: "empty handler",
			info: &runtime.ClusterRuntimeInfo{
				RuntimeClasses: []runtime.RuntimeClassInfo{
					{Name: "broken", Handler: ""},
				},
			},
			wantHit: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.info)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}
