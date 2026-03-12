package rules

import (
	"strings"
	"testing"
)

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
		name        string
		values      map[string]string
		wantHit     bool
		wantInsecure bool // message should mention "known-insecure"
	}{
		{"absent", map[string]string{}, true, false},
		{"safe ciphers only", map[string]string{
			"tls-cipher-suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		}, false, false},
		{"known-insecure RC4 cipher", map[string]string{
			"tls-cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_RC4_128_SHA",
		}, true, true},
		{"known-insecure 3DES cipher", map[string]string{
			"tls-cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		}, true, true},
		{"unrecognized (not known-insecure)", map[string]string{
			"tls-cipher-suites": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_UNKNOWN_CIPHER",
		}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
				return
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
				return
			}
			if tt.wantHit && tt.wantInsecure {
				if !strings.Contains(f.Message, "known-insecure") {
					t.Errorf("expected 'known-insecure' in message, got: %s", f.Message)
				}
			}
			if tt.wantHit && !tt.wantInsecure && f != nil {
				if strings.Contains(f.Message, "known-insecure") {
					t.Errorf("unexpected 'known-insecure' in message for unrecognized cipher: %s", f.Message)
				}
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
