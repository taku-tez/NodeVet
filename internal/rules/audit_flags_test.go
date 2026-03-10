package rules

import "testing"

func TestAuditLogPath(t *testing.T) {
	rule := ruleAuditLogPath
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"not set", map[string]string{}, true},
		{"set", map[string]string{"audit-log-path": "/var/log/audit.log"}, false},
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

func TestAuditLogMaxAge(t *testing.T) {
	rule := ruleAuditLogMaxAge
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"not set", map[string]string{}, true},
		{"29 days (too low)", map[string]string{"audit-log-maxage": "29"}, true},
		{"30 days (ok)", map[string]string{"audit-log-maxage": "30"}, false},
		{"90 days (ok)", map[string]string{"audit-log-maxage": "90"}, false},
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

func TestAuditLogMaxBackup(t *testing.T) {
	rule := ruleAuditLogMaxBackup
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"not set", map[string]string{}, true},
		{"5 (too low)", map[string]string{"audit-log-maxbackup": "5"}, true},
		{"10 (ok)", map[string]string{"audit-log-maxbackup": "10"}, false},
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

func TestAuditLogMaxSize(t *testing.T) {
	rule := ruleAuditLogMaxSize
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"not set", map[string]string{}, true},
		{"50 MB (too small)", map[string]string{"audit-log-maxsize": "50"}, true},
		{"100 MB (ok)", map[string]string{"audit-log-maxsize": "100"}, false},
		{"200 MB (ok)", map[string]string{"audit-log-maxsize": "200"}, false},
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

func TestAuditPolicyFile(t *testing.T) {
	rule := ruleAuditPolicyFile
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"not set", map[string]string{}, true},
		{"set", map[string]string{"audit-policy-file": "/etc/kubernetes/audit-policy.yaml"}, false},
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
