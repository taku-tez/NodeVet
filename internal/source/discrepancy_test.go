package source

import "testing"

func TestFindDiscrepancies(t *testing.T) {
	tests := []struct {
		name      string
		static    map[string]string
		live      map[string]string
		wantKeys  []string // expected discrepancy keys
		wantNone  bool
	}{
		{
			"no discrepancies",
			map[string]string{"anonymous-auth": "false", "read-only-port": "0"},
			map[string]string{"anonymous-auth": "false", "read-only-port": "0"},
			nil,
			true,
		},
		{
			"anonymous-auth drifted",
			map[string]string{"anonymous-auth": "false"},
			map[string]string{"anonymous-auth": "true"},
			[]string{"anonymous-auth"},
			false,
		},
		{
			"key only in live is not a discrepancy",
			map[string]string{"anonymous-auth": "false"},
			map[string]string{"anonymous-auth": "false", "rotate-certificates": "true"},
			nil,
			true,
		},
		{
			"key only in static is not a discrepancy",
			map[string]string{"anonymous-auth": "false", "client-ca-file": "/etc/k8s/ca.crt"},
			map[string]string{"anonymous-auth": "false"},
			nil,
			true,
		},
		{
			"multiple drifted keys",
			map[string]string{"anonymous-auth": "false", "read-only-port": "0", "authorization-mode": "Webhook"},
			map[string]string{"anonymous-auth": "true", "read-only-port": "10255", "authorization-mode": "Webhook"},
			[]string{"anonymous-auth", "read-only-port"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindDiscrepancies(tt.static, tt.live)
			if tt.wantNone {
				if len(got) != 0 {
					t.Errorf("expected no discrepancies, got %d: %v", len(got), got)
				}
				return
			}
			gotKeys := make(map[string]bool, len(got))
			for _, d := range got {
				gotKeys[d.Key] = true
			}
			for _, wk := range tt.wantKeys {
				if !gotKeys[wk] {
					t.Errorf("expected discrepancy for key %q, not found in %v", wk, got)
				}
			}
			if len(got) != len(tt.wantKeys) {
				t.Errorf("got %d discrepancies, want %d", len(got), len(tt.wantKeys))
			}
		})
	}
}
