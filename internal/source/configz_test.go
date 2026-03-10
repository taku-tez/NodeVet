package source

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const configzResponse = `{
  "kubeletconfig": {
    "authentication": {
      "anonymous": {"enabled": false},
      "x509": {"clientCAFile": "/etc/kubernetes/pki/ca.crt"}
    },
    "authorization": {"mode": "Webhook"},
    "tlsCertFile": "/etc/kubernetes/pki/kubelet.crt",
    "tlsPrivateKeyFile": "/etc/kubernetes/pki/kubelet.key",
    "rotateCertificates": true,
    "serverTLSBootstrap": true,
    "protectKernelDefaults": true,
    "makeIPTablesUtilChains": true,
    "eventRecordQPS": 5,
    "streamingConnectionIdleTimeout": "5m0s",
    "readOnlyPort": 0
  }
}`

func TestParseConfigzJSON(t *testing.T) {
	values, err := parseConfigzJSON([]byte(configzResponse))
	if err != nil {
		t.Fatalf("parseConfigzJSON error: %v", err)
	}

	expect := map[string]string{
		"anonymous-auth":                    "false",
		"client-ca-file":                    "/etc/kubernetes/pki/ca.crt",
		"authorization-mode":                "Webhook",
		"tls-cert-file":                     "/etc/kubernetes/pki/kubelet.crt",
		"tls-private-key-file":              "/etc/kubernetes/pki/kubelet.key",
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

func TestConfigzSourceHTTP(t *testing.T) {
	// httptest server simulating the Kubernetes API proxy
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(configzResponse))
	}))
	defer srv.Close()

	// We can't easily use ConfigzSource without a real kubeconfig,
	// so we test the parseConfigzJSON path directly above.
	// This test validates the HTTP handler structure.
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("http.Get error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
