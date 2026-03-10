package rules

import (
	"fmt"
	"strings"

	"github.com/NodeVet/nodevet/internal/access"
)

// AccessRule operates on ClusterAccessInfo.
type AccessRule struct {
	ID          string
	Title       string
	Severity    Severity
	Description string
	Remediation string
	Check       func(info *access.ClusterAccessInfo) []*AccessFinding
}

// AccessFinding is produced by an AccessRule.
type AccessFinding struct {
	Rule    *AccessRule
	Subject string // who has the dangerous permission
	Detail  string // role/binding name
	Actual  string
	Message string
}

// AccessResult holds all access control findings.
type AccessResult struct {
	Findings []*AccessFinding
	Passed   int
	Errors   int
	Warnings int
}

// NV3301: nodes/proxy access enables kubectl debug on any node
var ruleRBACNodeProxy = AccessRule{
	ID:          "NV3301",
	Title:       "RBAC: nodes/proxy access allows kubectl debug on any node",
	Severity:    SeverityError,
	Description: "One or more ClusterRoleBindings grant 'nodes/proxy' access. This allows the subject to run kubectl debug/exec on any node in the cluster.",
	Remediation: "Remove or scope the ClusterRole binding granting nodes/proxy. Restrict kubectl debug to cluster-admin only. Audit and remove unnecessary node-level access.",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, b := range info.NodeProxyBindings {
			subjects := access.FormatSubjects(b.Subjects)
			if subjects == "" {
				subjects = "(no subjects)"
			}
			findings = append(findings, &AccessFinding{
				Subject: subjects,
				Detail:  fmt.Sprintf("%s/%s", b.RoleKind, b.RoleName),
				Actual:  strings.Join(b.Verbs, ",") + " on nodes/proxy",
				Message: fmt.Sprintf("ClusterRole '%s' grants nodes/proxy to: %s", b.RoleName, subjects),
			})
		}
		return findings
	},
}

// NV3302: broad pods/exec access
var ruleRBACPodExec = AccessRule{
	ID:          "NV3302",
	Title:       "RBAC: broad pods/exec or pods/attach access detected",
	Severity:    SeverityWarn,
	Description: "One or more ClusterRoleBindings grant 'pods/exec' or 'pods/attach' at cluster scope. This allows arbitrary command execution in any pod.",
	Remediation: "Scope pods/exec permissions to specific namespaces using RoleBindings instead of ClusterRoleBindings. Remove this permission from broad groups like 'system:authenticated'.",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, b := range info.PodExecBindings {
			subjects := access.FormatSubjects(b.Subjects)
			if subjects == "" {
				subjects = "(no subjects)"
			}
			// Skip cluster-admin (expected to have all permissions)
			if b.RoleName == "cluster-admin" {
				continue
			}
			findings = append(findings, &AccessFinding{
				Subject: subjects,
				Detail:  fmt.Sprintf("%s/%s", b.RoleKind, b.RoleName),
				Actual:  strings.Join(b.Verbs, ",") + " on pods/exec",
				Message: fmt.Sprintf("ClusterRole '%s' grants pods/exec to: %s", b.RoleName, subjects),
			})
		}
		return findings
	},
}

// NV3303: pods with hostPID, hostNetwork, or hostIPC
var ruleHostPIDPods = AccessRule{
	ID:          "NV3303",
	Title:       "Privileged pods: hostPID/hostNetwork/hostIPC detected",
	Severity:    SeverityError,
	Description: "One or more pods use hostPID, hostNetwork, or hostIPC. These settings share the host's process/network/IPC namespace, enabling node escape attacks.",
	Remediation: "Remove hostPID/hostNetwork/hostIPC from pod specs unless absolutely required (e.g. system DaemonSets). Use PodSecurity admission to enforce restrictions.",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, pod := range info.RiskyPods {
			if !pod.HostPID && !pod.HostNetwork && !pod.HostIPC {
				continue
			}
			var flags []string
			if pod.HostPID {
				flags = append(flags, "hostPID")
			}
			if pod.HostNetwork {
				flags = append(flags, "hostNetwork")
			}
			if pod.HostIPC {
				flags = append(flags, "hostIPC")
			}
			findings = append(findings, &AccessFinding{
				Subject: fmt.Sprintf("%s/%s", pod.Namespace, pod.PodName),
				Detail:  strings.Join(flags, "+"),
				Actual:  strings.Join(flags, ", ") + "=true",
				Message: fmt.Sprintf("pod %s/%s uses %s; node escape path exists", pod.Namespace, pod.PodName, strings.Join(flags, "+")),
			})
		}
		return findings
	},
}

// NV3304: privileged containers or sensitive hostPath mounts
var rulePrivilegedPods = AccessRule{
	ID:          "NV3304",
	Title:       "Privileged pods: privileged containers or sensitive hostPath mounts",
	Severity:    SeverityError,
	Description: "One or more pods run privileged containers or mount sensitive host paths (/etc, /var/run, /proc, etc.). These configurations allow full node filesystem access.",
	Remediation: "Remove privileged:true from container SecurityContext. Replace sensitive hostPath mounts with emptyDir or persistent volumes. Use PodSecurity admission (Restricted policy).",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, pod := range info.RiskyPods {
			if !pod.Privileged && len(pod.HostPaths) == 0 {
				continue
			}
			var details []string
			if pod.Privileged {
				details = append(details, fmt.Sprintf("container %s is privileged", pod.ContainerName))
			}
			if len(pod.HostPaths) > 0 {
				details = append(details, fmt.Sprintf("hostPath: %s", strings.Join(pod.HostPaths, ", ")))
			}
			findings = append(findings, &AccessFinding{
				Subject: fmt.Sprintf("%s/%s", pod.Namespace, pod.PodName),
				Detail:  strings.Join(details, "; "),
				Actual:  strings.Join(details, "; "),
				Message: fmt.Sprintf("pod %s/%s: %s", pod.Namespace, pod.PodName, strings.Join(details, "; ")),
			})
		}
		return findings
	},
}

// AllAccessRules returns all access control rules (NV3301–NV3304).
func AllAccessRules() []AccessRule {
	all := []AccessRule{
		ruleRBACNodeProxy,
		ruleRBACPodExec,
		ruleHostPIDPods,
		rulePrivilegedPods,
	}
	for i := range all {
		r := &all[i]
		orig := r.Check
		r.Check = func(info *access.ClusterAccessInfo) []*AccessFinding {
			findings := orig(info)
			for _, f := range findings {
				f.Rule = r
			}
			return findings
		}
	}
	return all
}
