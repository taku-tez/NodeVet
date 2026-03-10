package rules

import (
	"fmt"
	"strings"

	"github.com/NodeVet/nodevet/internal/ebpf"
)

// NV6001: Falco DaemonSet must be deployed
var ruleFalcoDeployed = EBPFRule{
	ID:          "NV6001",
	Title:       "Falco: DaemonSet not deployed",
	Severity:    SeverityWarn,
	Description: "Falco is not deployed in the cluster. Without Falco, runtime security events (unexpected processes, file access, network connections) will not be detected.",
	Remediation: "Deploy Falco as a DaemonSet using the official Helm chart: helm repo add falcosecurity https://falcosecurity.github.io/charts && helm install falco falcosecurity/falco -n falco --create-namespace",
	Check: func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
		if info.Falco.Deployed {
			return nil
		}
		return &EBPFFinding{
			Actual:  "not deployed",
			Message: "Falco DaemonSet not found; runtime threat detection is unavailable",
		}
	},
}

// NV6002: Falco critical rules must not be disabled
var ruleFalcoCriticalRules = EBPFRule{
	ID:          "NV6002",
	Title:       "Falco: critical rules disabled via override",
	Severity:    SeverityError,
	Description: "One or more Falco critical rules are disabled via 'override: enabled: false'. This creates blind spots in runtime threat detection.",
	Remediation: "Remove 'override: enabled: false' from critical rules in your Falco rules ConfigMap. If a rule is too noisy, tune it with 'condition' overrides rather than disabling entirely.",
	Check: func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
		if !info.Falco.Deployed {
			return nil // covered by NV6001
		}
		var disabled []string
		for _, rf := range info.Falco.RulesFiles {
			disabled = append(disabled, rf.DisabledCritical...)
		}
		if len(disabled) == 0 {
			return nil
		}
		return &EBPFFinding{
			Actual:  fmt.Sprintf("disabled: %s", strings.Join(disabled, ", ")),
			Message: fmt.Sprintf("Falco critical rules disabled via override: %s", strings.Join(disabled, ", ")),
		}
	},
}

// NV6003: Falco must have output configured (webhook or gRPC for SIEM)
var ruleFalcoOutput = EBPFRule{
	ID:          "NV6003",
	Title:       "Falco: no external output (SIEM/webhook) configured",
	Severity:    SeverityWarn,
	Description: "Falco is deployed but no external output channel (HTTP webhook, Falcosidekick, gRPC) is configured. Alerts will only go to stdout and may not reach your SIEM.",
	Remediation: "Configure an HTTP webhook output or deploy Falcosidekick to forward Falco alerts to your SIEM/alerting system. Set http_output.enabled=true in the Falco configuration.",
	Check: func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
		if !info.Falco.Deployed {
			return nil // covered by NV6001
		}
		if info.Falco.OutputWebhook {
			return nil
		}
		return &EBPFFinding{
			Actual:  "no external output",
			Message: "Falco has no webhook/gRPC output configured; alerts will not reach SIEM",
		}
	},
}
