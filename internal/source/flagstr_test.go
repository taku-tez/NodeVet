package source

import (
	"testing"
)

func TestFlagSource(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect map[string]string
	}{
		{
			name:  "basic flags",
			input: "--anonymous-auth=false --tls-cert-file=/etc/k8s/kubelet.crt",
			expect: map[string]string{
				"anonymous-auth": "false",
				"tls-cert-file":  "/etc/k8s/kubelet.crt",
			},
		},
		{
			name:  "boolean flag without value",
			input: "--protect-kernel-defaults",
			expect: map[string]string{
				"protect-kernel-defaults": "true",
			},
		},
		{
			name:  "single dash flags",
			input: "-anonymous-auth=false",
			expect: map[string]string{
				"anonymous-auth": "false",
			},
		},
		{
			name:  "empty string",
			input: "",
			expect: map[string]string{},
		},
		{
			name:  "multiple spaces between flags",
			input: "--anonymous-auth=false   --read-only-port=0",
			expect: map[string]string{
				"anonymous-auth": "false",
				"read-only-port": "0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := NewFlagSource(tt.input)
			got, err := src.Load()
			if err != nil {
				t.Fatalf("Load() error: %v", err)
			}
			for k, wantV := range tt.expect {
				if gotV, ok := got[k]; !ok {
					t.Errorf("missing key %q", k)
				} else if gotV != wantV {
					t.Errorf("key %q: got %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}
