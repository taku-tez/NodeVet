package rules

import "strings"

// NV1001: anonymous-auth must be false
var ruleAnonymousAuth = Rule{
	ID:          "NV1001",
	Title:       "anonymous-auth must be disabled",
	Severity:    SeverityHigh,
	Description: "kubelet anonymous authentication is enabled (default: true). Unauthenticated requests to the kubelet API are allowed.",
	Remediation: "Set --anonymous-auth=false in kubelet configuration. In KubeletConfiguration YAML: authentication.anonymous.enabled: false",
	Check: func(values map[string]string) *Finding {
		// default is true (dangerous)
		if boolVal(values, "anonymous-auth", true) {
			actual := values["anonymous-auth"]
			if actual == "" {
				actual = "true (default)"
			}
			return &Finding{
				Actual:  actual,
				Message: "anonymous-auth is enabled; unauthenticated access to kubelet API is possible",
			}
		}
		return nil
	},
}

// NV1002: authorization-mode must not be AlwaysAllow
var ruleAuthorizationMode = Rule{
	ID:          "NV1002",
	Title:       "authorization-mode must not be AlwaysAllow",
	Severity:    SeverityHigh,
	Description: "kubelet authorization mode is AlwaysAllow or not set. All requests are authorized without any access control.",
	Remediation: "Set --authorization-mode=Webhook in kubelet configuration. In KubeletConfiguration YAML: authorization.mode: Webhook",
	Check: func(values map[string]string) *Finding {
		mode := strings.TrimSpace(stringVal(values, "authorization-mode"))
		if mode == "" || strings.EqualFold(mode, "AlwaysAllow") {
			actual := mode
			if actual == "" {
				actual = "AlwaysAllow (default)"
			}
			return &Finding{
				Actual:  actual,
				Message: "authorization-mode is AlwaysAllow; all requests are permitted without authorization",
			}
		}
		return nil
	},
}

// NV1003: client-ca-file must be set
var ruleClientCAFile = Rule{
	ID:          "NV1003",
	Title:       "client-ca-file must be configured",
	Severity:    SeverityHigh,
	Description: "kubelet client CA file is not configured. Client certificate authentication is disabled.",
	Remediation: "Set --client-ca-file=<path-to-ca.crt> in kubelet configuration. In KubeletConfiguration YAML: authentication.x509.clientCAFile: /etc/kubernetes/pki/ca.crt",
	Check: func(values map[string]string) *Finding {
		if stringVal(values, "client-ca-file") == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "client-ca-file is not configured; X.509 client certificate authentication is disabled",
			}
		}
		return nil
	},
}

// NV1004: read-only-port must be 0
var ruleReadOnlyPort = Rule{
	ID:          "NV1004",
	Title:       "read-only-port should be disabled",
	Severity:    SeverityMedium,
	Description: "kubelet read-only port (default: 10255) is enabled. This port exposes metrics and node information without authentication.",
	Remediation: "Set --read-only-port=0 in kubelet configuration. In KubeletConfiguration YAML: readOnlyPort: 0",
	Check: func(values map[string]string) *Finding {
		port := strings.TrimSpace(stringVal(values, "read-only-port"))
		if port == "" {
			// default is 10255 (dangerous)
			return &Finding{
				Actual:  "10255 (default)",
				Message: "read-only-port is open (default 10255); unauthenticated access to kubelet metrics",
			}
		}
		if port != "0" {
			return &Finding{
				Actual:  port,
				Message: "read-only-port is non-zero; unauthenticated access to kubelet metrics",
			}
		}
		return nil
	},
}
