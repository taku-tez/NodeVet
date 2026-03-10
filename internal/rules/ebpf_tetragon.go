package rules

import (
	"fmt"
	"strings"

	"github.com/NodeVet/nodevet/internal/ebpf"
)

// NV6101: Tetragon must be deployed with TracingPolicies
var ruleTetragonDeployed = EBPFRule{
	ID:          "NV6101",
	Title:       "Tetragon: not deployed or no TracingPolicies found",
	Severity:    SeverityMedium,
	Description: "Tetragon is not deployed or has no TracingPolicy resources. Without TracingPolicies, eBPF-level kernel tracing is not active.",
	Remediation: "Deploy Tetragon via Helm: helm install tetragon cilium/tetragon -n kube-system. Then apply TracingPolicy CRs to define which syscalls and kernel functions to trace.",
	Check: func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
		if info.Tetragon.Deployed && len(info.Tetragon.TracingPolicies) > 0 {
			return nil
		}
		if !info.Tetragon.Deployed {
			return &EBPFFinding{
				Actual:  "not deployed",
				Message: "Tetragon DaemonSet not found; kernel-level tracing is unavailable",
			}
		}
		return &EBPFFinding{
			Actual:  "no TracingPolicies",
			Message: "Tetragon is deployed but no TracingPolicy CRs found; no syscalls are being traced",
		}
	},
}

// NV6102: Tetragon must trace privileged operations (setuid/execve/capability changes)
var ruleTetragonPrivilegedOps = EBPFRule{
	ID:          "NV6102",
	Title:       "Tetragon: no TracingPolicy for privileged operations",
	Severity:    SeverityMedium,
	Description: "No Tetragon TracingPolicy is configured to trace privileged operations (setuid, execve, capability changes). Privilege escalation at kernel level will not be detected.",
	Remediation: "Apply a TracingPolicy that covers sys_enter_setuid, capability changes, and execve syscalls. Use the Tetragon example policies from the official documentation.",
	Check: func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
		if !info.Tetragon.Deployed || len(info.Tetragon.TracingPolicies) == 0 {
			return nil // covered by NV6101
		}
		if info.Tetragon.HasPrivilegedOp {
			return nil
		}
		names := strings.Join(info.Tetragon.TracingPolicies, ", ")
		return &EBPFFinding{
			Actual:  fmt.Sprintf("policies: %s", names),
			Message: fmt.Sprintf("TracingPolicies (%s) do not cover privileged ops (setuid/execve/capabilities)", names),
		}
	},
}
