package rules

import "github.com/NodeVet/nodevet/internal/ebpf"

// NV6201: Hubble must be enabled for network visibility
var ruleCiliumHubble = EBPFRule{
	ID:          "NV6201",
	Title:       "Cilium: Hubble not enabled",
	Severity:    SeverityWarn,
	Description: "Cilium is deployed but Hubble (network flow observability) is not enabled. Without Hubble, east-west traffic and network policy violations are not visible.",
	Remediation: "Enable Hubble by setting enable-hubble=true in the cilium-config ConfigMap, or install with: helm upgrade cilium cilium/cilium --set hubble.enabled=true",
	Check: func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
		if !info.Cilium.Deployed {
			return nil // Cilium not present; not applicable
		}
		if info.Cilium.HubbleEnabled {
			return nil
		}
		return &EBPFFinding{
			Actual:  "enable-hubble=false",
			Message: "Cilium Hubble is not enabled; network flow visibility and audit are unavailable",
		}
	},
}

// NV6202: Cilium L7 proxy must be enabled for HTTP/gRPC policy enforcement
var ruleCiliumL7Proxy = EBPFRule{
	ID:          "NV6202",
	Title:       "Cilium: L7 proxy (--enable-l7-proxy) not enabled",
	Severity:    SeverityWarn,
	Description: "Cilium is deployed but L7 proxy is not enabled. Without L7 proxy, HTTP/gRPC NetworkPolicies cannot inspect request attributes (paths, methods, headers).",
	Remediation: "Enable L7 proxy by setting enable-l7-proxy=true in the cilium-config ConfigMap, or install with: helm upgrade cilium cilium/cilium --set l7Proxy=true",
	Check: func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
		if !info.Cilium.Deployed {
			return nil // Cilium not present; not applicable
		}
		if info.Cilium.L7ProxyEnabled {
			return nil
		}
		return &EBPFFinding{
			Actual:  "enable-l7-proxy=false",
			Message: "Cilium L7 proxy is not enabled; HTTP/gRPC NetworkPolicy enforcement is unavailable",
		}
	},
}
