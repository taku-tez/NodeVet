package audit

import "testing"

func TestFindLevel_DirectMatch(t *testing.T) {
	policy, err := LoadPolicy("testdata/policy-complete.yaml")
	if err != nil {
		t.Fatalf("LoadPolicy error: %v", err)
	}

	tests := []struct {
		name      string
		op        AuditOperation
		wantLevel Level
	}{
		{"secrets get", AuditOperation{Verb: "get", Group: "", Resource: "secrets"}, LevelRequestResponse},
		{"pods/exec create", AuditOperation{Verb: "create", Group: "", Resource: "pods/exec"}, LevelRequest},
		{"system:anonymous get pods", AuditOperation{UserGroup: "system:anonymous", Verb: "get", Resource: "pods"}, LevelRequestResponse},
		{"rbac clusterrolebindings create", AuditOperation{Verb: "create", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}, LevelRequestResponse},
		{"generic deployment list", AuditOperation{Verb: "list", Group: "apps", Resource: "deployments"}, LevelMetadata},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.FindLevel(tt.op)
			if got != tt.wantLevel {
				t.Errorf("got %q, want %q", got, tt.wantLevel)
			}
		})
	}
}

func TestFindLevel_Incomplete(t *testing.T) {
	policy, err := LoadPolicy("testdata/policy-incomplete.yaml")
	if err != nil {
		t.Fatalf("LoadPolicy error: %v", err)
	}

	tests := []struct {
		name      string
		op        AuditOperation
		wantLevel Level
	}{
		{"secrets get → None (catch-all None)", AuditOperation{Verb: "get", Group: "", Resource: "secrets"}, LevelNone},
		{"anonymous → None", AuditOperation{UserGroup: "system:anonymous", Verb: "get", Resource: "pods"}, LevelNone},
		{"deployments → None (catch-all)", AuditOperation{Verb: "list", Group: "apps", Resource: "deployments"}, LevelNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policy.FindLevel(tt.op)
			if got != tt.wantLevel {
				t.Errorf("got %q, want %q", got, tt.wantLevel)
			}
		})
	}
}

func TestLevelAtLeast(t *testing.T) {
	tests := []struct {
		l    Level
		min  Level
		want bool
	}{
		{LevelRequestResponse, LevelRequest, true},
		{LevelRequest, LevelRequest, true},
		{LevelMetadata, LevelRequest, false},
		{LevelNone, LevelMetadata, false},
		{LevelRequestResponse, LevelNone, true},
	}
	for _, tt := range tests {
		t.Run(string(tt.l)+">="+string(tt.min), func(t *testing.T) {
			got := tt.l.AtLeast(tt.min)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseInvalidYAML(t *testing.T) {
	_, err := ParsePolicy([]byte("not: valid: yaml: [[["))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}
