package rules

import "testing"

func TestTLSCertFile(t *testing.T) {
	rule := ruleTLSCertFile
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent", map[string]string{}, true},
		{"set", map[string]string{"tls-cert-file": "/etc/k8s/kubelet.crt"}, false},
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

func TestTLSPrivateKeyFile(t *testing.T) {
	rule := ruleTLSPrivateKeyFile
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent", map[string]string{}, true},
		{"set", map[string]string{"tls-private-key-file": "/etc/k8s/kubelet.key"}, false},
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

func TestTLSCipherSuites(t *testing.T) {
	rule := ruleTLSCipherSuites
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent", map[string]string{}, true},
		{"safe ciphers only", map[string]string{
			"tls-cipher-suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		}, false},
		{"includes unsafe cipher", map[string]string{
			"tls-cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_RC4_128_SHA",
		}, true},
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

func TestRotateCertificates(t *testing.T) {
	rule := ruleRotateCertificates
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (default false)", map[string]string{}, true},
		{"false", map[string]string{"rotate-certificates": "false"}, true},
		{"true", map[string]string{"rotate-certificates": "true"}, false},
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

func TestRotateServerCertificates(t *testing.T) {
	rule := ruleRotateServerCertificates
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (default false)", map[string]string{}, true},
		{"false", map[string]string{"rotate-server-certificates": "false"}, true},
		{"true", map[string]string{"rotate-server-certificates": "true"}, false},
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
