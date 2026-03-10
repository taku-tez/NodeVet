package rules

import "testing"

func TestProtectKernelDefaults(t *testing.T) {
	rule := ruleProtectKernelDefaults
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (default false)", map[string]string{}, true},
		{"false", map[string]string{"protect-kernel-defaults": "false"}, true},
		{"true", map[string]string{"protect-kernel-defaults": "true"}, false},
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

func TestMakeIPTablesUtilChains(t *testing.T) {
	rule := ruleMakeIPTablesUtilChains
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (default true, no finding)", map[string]string{}, false},
		{"explicitly false", map[string]string{"make-iptables-util-chains": "false"}, true},
		{"explicitly true", map[string]string{"make-iptables-util-chains": "true"}, false},
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

func TestEventQPS(t *testing.T) {
	rule := ruleEventQPS
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (ok)", map[string]string{}, false},
		{"0 (dangerous)", map[string]string{"event-qps": "0"}, true},
		{"5 (ok)", map[string]string{"event-qps": "5"}, false},
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

func TestStreamingConnectionIdleTimeout(t *testing.T) {
	rule := ruleStreamingConnectionIdleTimeout
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent", map[string]string{}, true},
		{"0", map[string]string{"streaming-connection-idle-timeout": "0"}, true},
		{"0s", map[string]string{"streaming-connection-idle-timeout": "0s"}, true},
		{"5m", map[string]string{"streaming-connection-idle-timeout": "5m"}, false},
		{"5m0s", map[string]string{"streaming-connection-idle-timeout": "5m0s"}, false},
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
