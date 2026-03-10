package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// kube-apiserver audit log flag rules: NV5001–NV5006

// NV5001: audit-log-path must be set
var ruleAuditLogPath = Rule{
	ID:          "NV5001",
	Title:       "kube-apiserver: audit-log-path must be configured",
	Severity:    SeverityHigh,
	Description: "kube-apiserver audit-log-path is not set. Audit logging is disabled; security-relevant API events are not being recorded.",
	Remediation: "Set --audit-log-path=/var/log/kubernetes/audit.log in kube-apiserver configuration.",
	Check: func(values map[string]string) *Finding {
		if strings.TrimSpace(values["audit-log-path"]) == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "audit-log-path is not configured; audit logging is disabled",
			}
		}
		return nil
	},
}

// NV5002: audit-log-maxage should be >= 30 days (CIS 3.2.2)
var ruleAuditLogMaxAge = Rule{
	ID:          "NV5002",
	Title:       "kube-apiserver: audit-log-maxage should be at least 30 days",
	Severity:    SeverityMedium,
	Description: "kube-apiserver audit-log-maxage is not set or is less than 30 days. Audit logs may be deleted before they can be reviewed.",
	Remediation: "Set --audit-log-maxage=30 in kube-apiserver configuration. CIS Benchmark recommends >= 30 days.",
	Check: func(values map[string]string) *Finding {
		v := strings.TrimSpace(values["audit-log-maxage"])
		if v == "" {
			return &Finding{Actual: "(not set)", Message: "audit-log-maxage is not set; logs may be purged too quickly"}
		}
		days, err := strconv.Atoi(v)
		if err != nil || days < 30 {
			return &Finding{
				Actual:  v,
				Message: fmt.Sprintf("audit-log-maxage=%s is less than the recommended 30 days", v),
			}
		}
		return nil
	},
}

// NV5003: audit-log-maxbackup should be >= 10 (CIS 3.2.3)
var ruleAuditLogMaxBackup = Rule{
	ID:          "NV5003",
	Title:       "kube-apiserver: audit-log-maxbackup should be at least 10",
	Severity:    SeverityMedium,
	Description: "kube-apiserver audit-log-maxbackup is not set or is less than 10. Fewer retained log files reduces forensic visibility.",
	Remediation: "Set --audit-log-maxbackup=10 in kube-apiserver configuration. CIS Benchmark recommends >= 10.",
	Check: func(values map[string]string) *Finding {
		v := strings.TrimSpace(values["audit-log-maxbackup"])
		if v == "" {
			return &Finding{Actual: "(not set)", Message: "audit-log-maxbackup is not set; old log files may be discarded"}
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 10 {
			return &Finding{
				Actual:  v,
				Message: fmt.Sprintf("audit-log-maxbackup=%s is less than the recommended 10", v),
			}
		}
		return nil
	},
}

// NV5004: audit-log-maxsize should be >= 100 MB (CIS 3.2.4)
var ruleAuditLogMaxSize = Rule{
	ID:          "NV5004",
	Title:       "kube-apiserver: audit-log-maxsize should be at least 100 MB",
	Severity:    SeverityMedium,
	Description: "kube-apiserver audit-log-maxsize is not set or is less than 100 MB. Log rotation may occur too frequently, risking log loss under high API traffic.",
	Remediation: "Set --audit-log-maxsize=100 in kube-apiserver configuration. CIS Benchmark recommends >= 100 MB.",
	Check: func(values map[string]string) *Finding {
		v := strings.TrimSpace(values["audit-log-maxsize"])
		if v == "" {
			return &Finding{Actual: "(not set)", Message: "audit-log-maxsize is not set; default may be too small"}
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 100 {
			return &Finding{
				Actual:  v,
				Message: fmt.Sprintf("audit-log-maxsize=%s MB is less than the recommended 100 MB", v),
			}
		}
		return nil
	},
}

// NV5005: audit-policy-file must be set
var ruleAuditPolicyFile = Rule{
	ID:          "NV5005",
	Title:       "kube-apiserver: audit-policy-file must be configured",
	Severity:    SeverityHigh,
	Description: "kube-apiserver audit-policy-file is not set. Without a policy file, all requests are logged at the Metadata level (or not at all), missing request/response bodies for critical operations.",
	Remediation: "Create a comprehensive AuditPolicy YAML and set --audit-policy-file=/etc/kubernetes/audit-policy.yaml. Use 'nodevet audit --emit-policy' to generate a recommended policy.",
	Check: func(values map[string]string) *Finding {
		if strings.TrimSpace(values["audit-policy-file"]) == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "audit-policy-file is not configured; all events logged at default level only",
			}
		}
		return nil
	},
}

// NV5006: audit-webhook-config-file for external forwarding
var ruleAuditWebhookConfig = Rule{
	ID:          "NV5006",
	Title:       "kube-apiserver: audit webhook for external log forwarding should be configured",
	Severity:    SeverityMedium,
	Description: "kube-apiserver audit-webhook-config-file is not set. Audit logs are only stored locally and may be lost if the node is compromised or disk fills up.",
	Remediation: "Configure audit log forwarding to a SIEM or cloud logging service: --audit-webhook-config-file=/etc/kubernetes/audit-webhook.yaml. Supported backends: Cloud Logging, Datadog, Elastic, Fluentd.",
	Check: func(values map[string]string) *Finding {
		if strings.TrimSpace(values["audit-webhook-config-file"]) == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "audit-webhook-config-file is not set; logs stored locally only and may be tampered with",
			}
		}
		return nil
	},
}

// AllAuditFlagRules returns kube-apiserver audit log flag rules (NV5001–NV5006).
func AllAuditFlagRules() []Rule {
	all := []Rule{
		ruleAuditLogPath,
		ruleAuditLogMaxAge,
		ruleAuditLogMaxBackup,
		ruleAuditLogMaxSize,
		ruleAuditPolicyFile,
		ruleAuditWebhookConfig,
	}
	for i := range all {
		r := &all[i]
		orig := r.Check
		r.Check = func(values map[string]string) *Finding {
			f := orig(values)
			if f != nil {
				f.Rule = r
			}
			return f
		}
	}
	return all
}
