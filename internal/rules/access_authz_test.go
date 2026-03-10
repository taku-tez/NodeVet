package rules

import "testing"

func TestAPIServerNodeAuthorizer(t *testing.T) {
	rule := ruleAPIServerNodeAuthorizer
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"not set", map[string]string{}, true},
		{"Node,RBAC", map[string]string{"authorization-mode": "Node,RBAC"}, false},
		{"RBAC only", map[string]string{"authorization-mode": "RBAC"}, true},
		{"AlwaysAllow", map[string]string{"authorization-mode": "AlwaysAllow"}, true},
		{"Node only", map[string]string{"authorization-mode": "Node"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestAPIServerNodeRestriction(t *testing.T) {
	rule := ruleAPIServerNodeRestriction
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"not set", map[string]string{}, true},
		{"NodeRestriction present", map[string]string{"enable-admission-plugins": "NodeRestriction,PodSecurity"}, false},
		{"missing NodeRestriction", map[string]string{"enable-admission-plugins": "PodSecurity,ResourceQuota"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}
