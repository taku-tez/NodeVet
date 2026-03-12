package rules

import (
	"strings"
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
		{
			"cluster-admin skipped",
			makeClusterAccessInfo([]access.RBACBinding{
				{RoleKind: "ClusterRole", RoleName: "cluster-admin", Verbs: []string{"*"}, Subjects: []access.Subject{{Kind: "User", Name: "admin"}}},
			}, nil, nil),
			0,
		},
		{
			"system: role skipped",
			makeClusterAccessInfo([]access.RBACBinding{
				{RoleKind: "ClusterRole", RoleName: "system:node", Verbs: []string{"get"}, Subjects: []access.Subject{{Kind: "Group", Name: "system:nodes"}}},
			}, nil, nil),
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
			"system: role skipped",
			makeClusterAccessInfo(nil, []access.RBACBinding{
				{RoleKind: "ClusterRole", RoleName: "system:controller:attachdetach-controller", Verbs: []string{"create"}, Subjects: []access.Subject{{Kind: "ServiceAccount", Name: "attachdetach-controller"}}},
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
			"system namespace skipped",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "kube-system", PodName: "net-pod", HostNetwork: true, HostIPC: true, IsSystemNamespace: true},
			}),
			0,
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
		{
			"system namespace skipped",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "kube-system", PodName: "storage-driver", ContainerName: "driver", Privileged: true, IsSystemNamespace: true},
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

func TestRBACDangerousSubjectEscalation(t *testing.T) {
	t.Run("NV3301 system:authenticated escalates to CRITICAL", func(t *testing.T) {
		rule := ruleRBACNodeProxy
		info := makeClusterAccessInfo([]access.RBACBinding{
			{
				RoleKind: "ClusterRole",
				RoleName: "node-debugger",
				Verbs:    []string{"get"},
				Subjects: []access.Subject{{Kind: "Group", Name: "system:authenticated"}},
			},
		}, nil, nil)
		findings := rule.Check(info)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		f := findings[0]
		if f.SeverityOverride == nil || *f.SeverityOverride != SeverityCritical {
			t.Errorf("expected SeverityOverride=CRITICAL, got %v", f.SeverityOverride)
		}
	})

	t.Run("NV3302 named SA does not escalate", func(t *testing.T) {
		rule := ruleRBACPodExec
		info := makeClusterAccessInfo(nil, []access.RBACBinding{
			{
				RoleKind: "ClusterRole",
				RoleName: "exec-role",
				Verbs:    []string{"create"},
				Subjects: []access.Subject{{Kind: "ServiceAccount", Name: "ci-runner", Namespace: "build"}},
			},
		}, nil)
		findings := rule.Check(info)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].SeverityOverride != nil {
			t.Errorf("expected no SeverityOverride for named SA, got %v", findings[0].SeverityOverride)
		}
	})

	t.Run("NV3302 namespace-scoped binding shows namespace in detail", func(t *testing.T) {
		rule := ruleRBACPodExec
		info := makeClusterAccessInfo(nil, []access.RBACBinding{
			{
				RoleKind:  "Role",
				RoleName:  "exec-role",
				Namespace: "production",
				Verbs:     []string{"create"},
				Subjects:  []access.Subject{{Kind: "Group", Name: "developers"}},
			},
		}, nil)
		findings := rule.Check(info)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if !strings.Contains(findings[0].Detail, "production") {
			t.Errorf("expected 'production' in Detail, got: %s", findings[0].Detail)
		}
	})
}

func TestNodeEscapeChain(t *testing.T) {
	rule := ruleNodeEscapeChain
	tests := []struct {
		name      string
		info      *access.ClusterAccessInfo
		wantCount int
	}{
		{"no risky pods", makeClusterAccessInfo(nil, nil, nil), 0},
		{
			"privileged only (no host namespace)",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "priv-only", Privileged: true},
			}),
			0,
		},
		{
			"hostPID only (not privileged)",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "hostpid-only", HostPID: true},
			}),
			0,
		},
		{
			"hostPID + privileged = CRITICAL chain",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "default", PodName: "escape-pod", ContainerName: "app", HostPID: true, Privileged: true},
			}),
			1,
		},
		{
			"hostNetwork + privileged = CRITICAL chain",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "production", PodName: "net-priv-pod", ContainerName: "app", HostNetwork: true, Privileged: true},
			}),
			1,
		},
		{
			"system namespace skipped even with chain",
			makeClusterAccessInfo(nil, nil, []access.PodRisk{
				{Namespace: "kube-system", PodName: "system-pod", HostPID: true, Privileged: true, IsSystemNamespace: true},
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
