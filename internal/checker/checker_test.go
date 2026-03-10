package checker

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/source"
)

type mockSource struct {
	name   string
	values map[string]string
}

func (m *mockSource) Load() (map[string]string, error) { return m.values, nil }
func (m *mockSource) SourceName() string               { return m.name }

func TestCheckerAllInsecure(t *testing.T) {
	c := &Checker{
		Sources: []source.ConfigSource{
			&mockSource{name: "mock", values: map[string]string{}},
		},
		Rules: rules.All(),
	}
	result, err := c.Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if result.Errors == 0 {
		t.Error("expected errors for empty config, got 0")
	}
	errorRuleIDs := make(map[string]bool)
	for _, f := range result.Findings {
		if rules.SeverityIsHighOrAbove(f.Rule.Severity) {
			errorRuleIDs[f.Rule.ID] = true
		}
	}
	mustFire := []string{"NV1001", "NV1002", "NV1003", "NV1101", "NV1102"}
	for _, id := range mustFire {
		if !errorRuleIDs[id] {
			t.Errorf("expected HIGH/CRITICAL rule %s to fire, but it did not", id)
		}
	}
}

func TestCheckerAllSecure(t *testing.T) {
	secureConfig := map[string]string{
		"anonymous-auth":                    "false",
		"authorization-mode":                "Webhook",
		"client-ca-file":                    "/etc/kubernetes/pki/ca.crt",
		"read-only-port":                    "0",
		"tls-cert-file":                     "/etc/kubernetes/pki/kubelet.crt",
		"tls-private-key-file":              "/etc/kubernetes/pki/kubelet.key",
		"tls-cipher-suites":                 "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		"rotate-certificates":               "true",
		"rotate-server-certificates":        "true",
		"protect-kernel-defaults":           "true",
		"make-iptables-util-chains":         "true",
		"event-qps":                         "5",
		"streaming-connection-idle-timeout": "5m0s",
	}
	c := &Checker{
		Sources: []source.ConfigSource{
			&mockSource{name: "mock", values: secureConfig},
		},
		Rules: rules.All(),
	}
	result, err := c.Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if len(result.Findings) != 0 {
		for _, f := range result.Findings {
			t.Errorf("unexpected finding: %s %s", f.Rule.ID, f.Message)
		}
	}
}

func TestCheckerMergeSourcePrecedence(t *testing.T) {
	c := &Checker{
		Sources: []source.ConfigSource{
			&mockSource{name: "yaml", values: map[string]string{"anonymous-auth": "true"}},
			&mockSource{name: "flags", values: map[string]string{"anonymous-auth": "false"}},
		},
		Rules: rules.All(),
	}
	result, err := c.Run()
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range result.Findings {
		if f.Rule.ID == "NV1001" {
			t.Error("NV1001 should not fire when flags override yaml with anonymous-auth=false")
		}
	}
}
