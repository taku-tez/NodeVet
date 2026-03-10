package access

import (
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestRuleGrantsNodeProxy(t *testing.T) {
	tests := []struct {
		name string
		rule rbacv1.PolicyRule
		want bool
	}{
		{
			"nodes/proxy with get",
			rbacv1.PolicyRule{Resources: []string{"nodes/proxy"}, Verbs: []string{"get"}},
			true,
		},
		{
			"nodes/* with create",
			rbacv1.PolicyRule{Resources: []string{"nodes/*"}, Verbs: []string{"create"}},
			true,
		},
		{
			"nodes/proxy with list only (not dangerous)",
			rbacv1.PolicyRule{Resources: []string{"nodes/proxy"}, Verbs: []string{"list"}},
			false,
		},
		{
			"pods only",
			rbacv1.PolicyRule{Resources: []string{"pods"}, Verbs: []string{"get"}},
			false,
		},
		{
			"wildcard resource and verb",
			rbacv1.PolicyRule{Resources: []string{"*"}, Verbs: []string{"*"}},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleGrantsNodeProxy(tt.rule)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRuleGrantsPodExec(t *testing.T) {
	tests := []struct {
		name string
		rule rbacv1.PolicyRule
		want bool
	}{
		{
			"pods/exec with create",
			rbacv1.PolicyRule{Resources: []string{"pods/exec"}, Verbs: []string{"create"}},
			true,
		},
		{
			"pods/attach with get",
			rbacv1.PolicyRule{Resources: []string{"pods/attach"}, Verbs: []string{"get"}},
			true,
		},
		{
			"pods/* with create",
			rbacv1.PolicyRule{Resources: []string{"pods/*"}, Verbs: []string{"create"}},
			true,
		},
		{
			"pods only (no exec)",
			rbacv1.PolicyRule{Resources: []string{"pods"}, Verbs: []string{"get", "list"}},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleGrantsPodExec(tt.rule)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFormatSubjects(t *testing.T) {
	subjects := []Subject{
		{Kind: "User", Name: "alice"},
		{Kind: "Group", Name: "developers"},
		{Kind: "ServiceAccount", Name: "default", Namespace: "kube-system"},
	}
	got := FormatSubjects(subjects)
	expected := "User:alice, Group:developers, SA:kube-system/default"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}
