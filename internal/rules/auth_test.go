package rules

import "testing"

func TestAnonymousAuth(t *testing.T) {
	rule := ruleAnonymousAuth
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (default true)", map[string]string{}, true},
		{"explicitly true", map[string]string{"anonymous-auth": "true"}, true},
		{"explicitly false", map[string]string{"anonymous-auth": "false"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("expected nil, got finding: %s", f.Message)
			}
		})
	}
}

func TestAuthorizationMode(t *testing.T) {
	rule := ruleAuthorizationMode
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent", map[string]string{}, true},
		{"AlwaysAllow", map[string]string{"authorization-mode": "AlwaysAllow"}, true},
		{"alwaysallow lowercase", map[string]string{"authorization-mode": "alwaysallow"}, true},
		{"Webhook", map[string]string{"authorization-mode": "Webhook"}, false},
		{"Node", map[string]string{"authorization-mode": "Node"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("expected nil, got finding: %s", f.Message)
			}
		})
	}
}

func TestClientCAFile(t *testing.T) {
	rule := ruleClientCAFile
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent", map[string]string{}, true},
		{"empty string", map[string]string{"client-ca-file": ""}, true},
		{"set", map[string]string{"client-ca-file": "/etc/kubernetes/pki/ca.crt"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("expected nil, got finding: %s", f.Message)
			}
		})
	}
}

func TestReadOnlyPort(t *testing.T) {
	rule := ruleReadOnlyPort
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (default 10255)", map[string]string{}, true},
		{"10255", map[string]string{"read-only-port": "10255"}, true},
		{"0 (disabled)", map[string]string{"read-only-port": "0"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("expected nil, got finding: %s", f.Message)
			}
		})
	}
}
