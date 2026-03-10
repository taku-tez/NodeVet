package rules

import "strings"

// NV1201: protect-kernel-defaults must be true
var ruleProtectKernelDefaults = Rule{
	ID:          "NV1201",
	Title:       "protect-kernel-defaults should be enabled",
	Severity:    SeverityWarn,
	Description: "kubelet protect-kernel-defaults is disabled. Containers may modify kernel parameters.",
	Remediation: "Set --protect-kernel-defaults=true in kubelet configuration. In KubeletConfiguration YAML: protectKernelDefaults: true",
	Check: func(values map[string]string) *Finding {
		if !boolVal(values, "protect-kernel-defaults", false) {
			actual := values["protect-kernel-defaults"]
			if actual == "" {
				actual = "false (default)"
			}
			return &Finding{
				Actual:  actual,
				Message: "protect-kernel-defaults is disabled; containers may tune kernel parameters",
			}
		}
		return nil
	},
}

// NV1202: make-iptables-util-chains must be true
var ruleMakeIPTablesUtilChains = Rule{
	ID:          "NV1202",
	Title:       "make-iptables-util-chains should be enabled",
	Severity:    SeverityWarn,
	Description: "kubelet make-iptables-util-chains is disabled. iptables utility chains may conflict with host rules.",
	Remediation: "Set --make-iptables-util-chains=true in kubelet configuration. In KubeletConfiguration YAML: makeIPTablesUtilChains: true",
	Check: func(values map[string]string) *Finding {
		// default is true, so only flag if explicitly set to false
		if v, ok := values["make-iptables-util-chains"]; ok {
			if !boolVal(values, "make-iptables-util-chains", true) {
				return &Finding{
					Actual:  v,
					Message: "make-iptables-util-chains is disabled; potential iptables rule conflicts",
				}
			}
		}
		return nil
	},
}

// NV1203: event-qps must not be 0
var ruleEventQPS = Rule{
	ID:          "NV1203",
	Title:       "event-qps should not be 0",
	Severity:    SeverityWarn,
	Description: "kubelet event-qps is set to 0, which disables rate limiting on event generation. This can be exploited for DoS attacks.",
	Remediation: "Set --event-qps=5 (or a positive value) in kubelet configuration. In KubeletConfiguration YAML: eventRecordQPS: 5",
	Check: func(values map[string]string) *Finding {
		qps := strings.TrimSpace(stringVal(values, "event-qps"))
		if qps == "0" {
			return &Finding{
				Actual:  "0",
				Message: "event-qps=0 disables rate limiting on event recording; potential DoS vector",
			}
		}
		return nil
	},
}

// NV1204: streaming-connection-idle-timeout must not be 0
var ruleStreamingConnectionIdleTimeout = Rule{
	ID:          "NV1204",
	Title:       "streaming-connection-idle-timeout should not be 0",
	Severity:    SeverityWarn,
	Description: "kubelet streaming-connection-idle-timeout is not set or 0. exec/attach streams never time out.",
	Remediation: "Set --streaming-connection-idle-timeout=5m in kubelet configuration. In KubeletConfiguration YAML: streamingConnectionIdleTimeout: 5m0s",
	Check: func(values map[string]string) *Finding {
		timeout := strings.TrimSpace(stringVal(values, "streaming-connection-idle-timeout"))
		if timeout == "" || timeout == "0" || timeout == "0s" {
			actual := timeout
			if actual == "" {
				actual = "(not set)"
			}
			return &Finding{
				Actual:  actual,
				Message: "streaming-connection-idle-timeout is not set; exec/attach connections may never time out",
			}
		}
		return nil
	},
}
