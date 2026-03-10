package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/access"
)

func makeClusterAccessInfo(nodeProxy, podExec []access.RBACBinding, pods []access.PodRisk) *access.ClusterAccessInfo {
	return &access.ClusterAccessInfo{
		NodeProxyBindings: nodeProxy,
		PodExecBindings:   podExec,
		RiskyPods:         pods,
	}
}

func TestRBACNodeProxy(t *testing.T) {
	rule := ruleRBACNodeProxy
	tests := []struct {
		name      string
		info      *access.ClusterAccessInfo
		wantCount int
	}{
		{"no bindings", makeClusterAccessInfo(nil, nil, nil), 0},
		{
			"one binding",
			makeClusterAccessInfo([]access.RBACBinding{
				{
					RoleKind: "ClusterRole",
					RoleName: "node-debugger",
					Verbs:    []string{"get", "create"},
					Subjects: []access.Subject{{Kind: "User", Name: "alice"}},
				},
			}, nil, nil),
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Check(tt.info)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantCount)
			}
		})
	}
}

func TestRBACPodExec(t *testing.T) {
	rule := ruleRBACPodExec
	tests := []struct {
		name      string
		info      *access.ClusterAccessInfo
		wantCount int
	}{
		{"no bindings", makeClusterAccessInfo(nil, nil, nil), 0},
		{
			"cluster-admin skipped",
			makeClusterAccessInfo(nil, []access.RBACBinding{
				{RoleKind: "ClusterRole", RoleName: "cluster-admin", Verbs: []string{"*"}, Subjects: []access.Subject{{Kind: "User", Name: "admin"}}},
			}, nil),
			0,
		},
		{
			"custom role with pods/exec",
			makeClusterAccessInfo(nil, []access.RBACBinding{
				{RoleKind: "ClusterRole", RoleName: "exec-role", Verbs: []string{"create"}, Subjects: []access.Subject{{Kind: "Group", Name: "developers"}}},
			}, nil),
			1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Check(tt.info)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantCount)
			}
		})
	}
}

func TestHostPIDPods(t *testing.T) {
	rule := ruleHostPIDPods
	tests := []struct {
		name      string
		info      *access.ClusterAccessInfo
		wantCount int
	}{
		{"no risky pods", makeClusterAccessInfo(nil, nil, nil), 0},
		{
			"pod with hostPID",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "risky-pod", HostPID: true},
			}),
			1,
		},
		{
			"pod with hostNetwork + hostIPC",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "kube-system", PodName: "net-pod", HostNetwork: true, HostIPC: true},
			}),
			1,
		},
		{
			"normal pod (only privileged, no host namespaces)",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "priv-pod", Privileged: true},
			}),
			0, // NV3303 doesn't catch this; NV3304 does
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Check(tt.info)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantCount)
			}
		})
	}
}

func TestPrivilegedPods(t *testing.T) {
	rule := rulePrivilegedPods
	tests := []struct {
		name      string
		info      *access.ClusterAccessInfo
		wantCount int
	}{
		{"no risky pods", makeClusterAccessInfo(nil, nil, nil), 0},
		{
			"privileged container",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "priv-pod", ContainerName: "app", Privileged: true},
			}),
			1,
		},
		{
			"sensitive hostPath",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "host-pod", HostPaths: []string{"/etc"}},
			}),
			1,
		},
		{
			"hostPID only (not caught by NV3304)",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "pid-pod", HostPID: true},
			}),
			0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := rule.Check(tt.info)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(findings), tt.wantCount)
			}
		})
	}
}
