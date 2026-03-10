package rules

import (
	"fmt"
	"strings"
)

// safeCipherSuites is the CIS Kubernetes Benchmark 1.9 recommended cipher suites.
var safeCipherSuites = map[string]bool{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": true,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   true,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305":  true,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305":    true,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": true,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   true,
}

// NV1101: tls-cert-file must be set
var ruleTLSCertFile = Rule{
	ID:          "NV1101",
	Title:       "tls-cert-file must be configured",
	Severity:    SeverityError,
	Description: "kubelet TLS certificate file is not configured. The kubelet API server is running without TLS.",
	Remediation: "Set --tls-cert-file=<path> in kubelet configuration. In KubeletConfiguration YAML: tlsCertFile: /etc/kubernetes/pki/kubelet.crt",
	Check: func(values map[string]string) *Finding {
		if stringVal(values, "tls-cert-file") == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "tls-cert-file is not configured; kubelet API may be exposed without TLS",
			}
		}
		return nil
	},
}

// NV1102: tls-private-key-file must be set
var ruleTLSPrivateKeyFile = Rule{
	ID:          "NV1102",
	Title:       "tls-private-key-file must be configured",
	Severity:    SeverityError,
	Description: "kubelet TLS private key file is not configured. The kubelet API server is running without TLS.",
	Remediation: "Set --tls-private-key-file=<path> in kubelet configuration. In KubeletConfiguration YAML: tlsPrivateKeyFile: /etc/kubernetes/pki/kubelet.key",
	Check: func(values map[string]string) *Finding {
		if stringVal(values, "tls-private-key-file") == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "tls-private-key-file is not configured; kubelet API may be exposed without TLS",
			}
		}
		return nil
	},
}

// NV1103: tls-cipher-suites must use safe ciphers
var ruleTLSCipherSuites = Rule{
	ID:          "NV1103",
	Title:       "tls-cipher-suites should use secure ciphers only",
	Severity:    SeverityWarn,
	Description: "kubelet TLS cipher suites are not explicitly configured, or include weak ciphers.",
	Remediation: "Set --tls-cipher-suites to a safe list: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,...",
	Check: func(values map[string]string) *Finding {
		suites := strings.TrimSpace(stringVal(values, "tls-cipher-suites"))
		if suites == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "tls-cipher-suites is not configured; weak ciphers may be allowed by default",
			}
		}
		var unsafe []string
		for _, suite := range strings.Split(suites, ",") {
			s := strings.TrimSpace(suite)
			if s != "" && !safeCipherSuites[s] {
				unsafe = append(unsafe, s)
			}
		}
		if len(unsafe) > 0 {
			return &Finding{
				Actual:  suites,
				Message: fmt.Sprintf("unsafe cipher suites detected: %s", strings.Join(unsafe, ", ")),
			}
		}
		return nil
	},
}

// NV1104: rotate-certificates must be true
var ruleRotateCertificates = Rule{
	ID:          "NV1104",
	Title:       "rotate-certificates should be enabled",
	Severity:    SeverityWarn,
	Description: "kubelet client certificate rotation is disabled. Certificates must be rotated manually.",
	Remediation: "Set --rotate-certificates=true in kubelet configuration. In KubeletConfiguration YAML: rotateCertificates: true",
	Check: func(values map[string]string) *Finding {
		if !boolVal(values, "rotate-certificates", false) {
			actual := values["rotate-certificates"]
			if actual == "" {
				actual = "false (default)"
			}
			return &Finding{
				Actual:  actual,
				Message: "rotate-certificates is disabled; manual certificate rotation required",
			}
		}
		return nil
	},
}

// NV1105: rotate-server-certificates must be true
var ruleRotateServerCertificates = Rule{
	ID:          "NV1105",
	Title:       "rotate-server-certificates should be enabled",
	Severity:    SeverityWarn,
	Description: "kubelet server certificate rotation is disabled. Server certificates must be rotated manually.",
	Remediation: "Set --rotate-server-certificates=true in kubelet configuration. In KubeletConfiguration YAML: serverTLSBootstrap: true",
	Check: func(values map[string]string) *Finding {
		if !boolVal(values, "rotate-server-certificates", false) {
			actual := values["rotate-server-certificates"]
			if actual == "" {
				actual = "false (default)"
			}
			return &Finding{
				Actual:  actual,
				Message: "rotate-server-certificates is disabled; manual server certificate rotation required",
			}
		}
		return nil
	},
}
