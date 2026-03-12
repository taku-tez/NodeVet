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

// knownInsecureSuites contains cipher suites with confirmed cryptographic weaknesses.
// These should be treated as errors, not warnings.
var knownInsecureSuites = map[string]bool{
	// RC4: broken stream cipher (BEAST, RC4 biases)
	"TLS_RSA_WITH_RC4_128_SHA":         true,
	"TLS_ECDHE_RSA_WITH_RC4_128_SHA":   true,
	"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA": true,
	// NULL: no encryption
	"TLS_RSA_WITH_NULL_SHA":    true,
	"TLS_RSA_WITH_NULL_SHA256": true,
	"TLS_RSA_WITH_NULL_MD5":    true,
	// 3DES: SWEET32 (birthday attack) vulnerability
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":       true,
	"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": true,
	// DES: broken
	"TLS_RSA_WITH_DES_CBC_SHA": true,
	// Anonymous: no server authentication
	"TLS_DH_anon_WITH_AES_128_CBC_SHA":  true,
	"TLS_DH_anon_WITH_AES_256_CBC_SHA":  true,
	"TLS_ECDH_anon_WITH_AES_128_CBC_SHA": true,
	"TLS_ECDH_anon_WITH_AES_256_CBC_SHA": true,
	// EXPORT: intentionally weakened for export regulations (Logjam, FREAK)
	"TLS_RSA_EXPORT_WITH_RC4_40_MD5":  true,
	"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA": true,
}

// NV1101: tls-cert-file must be set
var ruleTLSCertFile = Rule{
	ID:          "NV1101",
	Title:       "tls-cert-file must be configured",
	Severity:    SeverityHigh,
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
	Severity:    SeverityHigh,
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
	Severity:    SeverityMedium,
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
		var insecure, unrecognized []string
		for _, suite := range strings.Split(suites, ",") {
			s := strings.TrimSpace(suite)
			if s == "" {
				continue
			}
			if knownInsecureSuites[s] {
				insecure = append(insecure, s)
			} else if !safeCipherSuites[s] {
				unrecognized = append(unrecognized, s)
			}
		}
		if len(insecure) == 0 && len(unrecognized) == 0 {
			return nil
		}
		var parts []string
		if len(insecure) > 0 {
			parts = append(parts, fmt.Sprintf("known-insecure (RC4/NULL/3DES/EXPORT): %s", strings.Join(insecure, ", ")))
		}
		if len(unrecognized) > 0 {
			parts = append(parts, fmt.Sprintf("not in recommended list: %s", strings.Join(unrecognized, ", ")))
		}
		return &Finding{
			Actual:  suites,
			Message: strings.Join(parts, "; "),
		}
	},
}

// NV1104: rotate-certificates must be true
var ruleRotateCertificates = Rule{
	ID:          "NV1104",
	Title:       "rotate-certificates should be enabled",
	Severity:    SeverityMedium,
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
	Severity:    SeverityMedium,
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
