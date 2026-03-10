package source

import (
	"testing"
)

func TestYAMLSourceSecure(t *testing.T) {
	src := NewYAMLSource("testdata/kubelet-config-secure.yaml")
	values, err := src.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	expect := map[string]string{
		"anonymous-auth":                    "false",
		"client-ca-file":                    "/etc/kubernetes/pki/ca.crt",
		"authorization-mode":                "Webhook",
		"tls-cert-file":                     "/etc/kubernetes/pki/kubelet.crt",
		"tls-private-key-file":              "/etc/kubernetes/pki/kubelet.key",
		"tls-cipher-suites":                 "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"rotate-certificates":               "true",
		"rotate-server-certificates":        "true",
		"protect-kernel-defaults":           "true",
		"make-iptables-util-chains":         "true",
		"event-qps":                         "5",
		"streaming-connection-idle-timeout": "5m0s",
		"read-only-port":                    "0",
	}

	for k, wantV := range expect {
		if gotV, ok := values[k]; !ok {
			t.Errorf("missing key %q", k)
		} else if gotV != wantV {
			t.Errorf("key %q: got %q, want %q", k, gotV, wantV)
		}
	}
}

func TestYAMLSourceInsecure(t *testing.T) {
	src := NewYAMLSource("testdata/kubelet-config-insecure.yaml")
	values, err := src.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	expect := map[string]string{
		"anonymous-auth":                    "true",
		"authorization-mode":                "AlwaysAllow",
		"read-only-port":                    "10255",
		"event-qps":                         "0",
		"streaming-connection-idle-timeout": "0s",
		"make-iptables-util-chains":         "false",
	}

	for k, wantV := range expect {
		if gotV, ok := values[k]; !ok {
			t.Errorf("missing key %q", k)
		} else if gotV != wantV {
			t.Errorf("key %q: got %q, want %q", k, gotV, wantV)
		}
	}
}

func TestParseKubeletConfigYAML_InvalidYAML(t *testing.T) {
	_, err := ParseKubeletConfigYAML([]byte("not: valid: yaml: ["))
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}
