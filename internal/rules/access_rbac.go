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
	Rule             *AccessRule
	Subject          string    // who has the dangerous permission
	Detail           string    // role/binding name
	Actual           string
	Message          string
	SeverityOverride *Severity // if non-nil, overrides Rule.Severity for this finding
}

// EffectiveSeverity returns SeverityOverride if set, otherwise Rule.Severity.
func (f *AccessFinding) EffectiveSeverity() Severity {
	if f.SeverityOverride != nil {
		return *f.SeverityOverride
	}
	return f.Rule.Severity
}

// dangerousSubjects are groups that effectively grant access to all or most users in the cluster.
var dangerousSubjects = map[string]bool{
	"system:authenticated":   true,
	"system:unauthenticated": true,
	"system:serviceaccounts": true,
}

// hasDangerousSubject returns true if any subject is a broad system group.
func hasDangerousSubject(subjects []access.Subject) bool {
	for _, s := range subjects {
		if s.Kind == "Group" && dangerousSubjects[s.Name] {
			return true
		}
	}
	return false
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
	Severity:    SeverityHigh,
	Description: "One or more ClusterRoleBindings grant 'nodes/proxy' access. This allows the subject to run kubectl debug/exec on any node in the cluster.",
	Remediation: "Remove or scope the ClusterRole binding granting nodes/proxy. Restrict kubectl debug to cluster-admin only. Audit and remove unnecessary node-level access.",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, b := range info.NodeProxyBindings {
			// cluster-admin and built-in system: roles are expected to have this permission.
			if b.RoleName == "cluster-admin" || strings.HasPrefix(b.RoleName, "system:") {
				continue
			}
			subjects := access.FormatSubjects(b.Subjects)
			if subjects == "" {
				subjects = "(no subjects)"
			}
			f := &AccessFinding{
				Subject: subjects,
				Detail:  fmt.Sprintf("%s/%s", b.RoleKind, b.RoleName),
				Actual:  strings.Join(b.Verbs, ",") + " on nodes/proxy",
				Message: fmt.Sprintf("ClusterRole '%s' grants nodes/proxy to: %s", b.RoleName, subjects),
			}
			if hasDangerousSubject(b.Subjects) {
				sev := SeverityCritical
				f.SeverityOverride = &sev
				f.Message += " [ESCALATED: broad system group has cluster-wide node access]"
			}
			findings = append(findings, f)
		}
		return findings
	},
}

// NV3302: broad pods/exec access
var ruleRBACPodExec = AccessRule{
	ID:          "NV3302",
	Title:       "RBAC: broad pods/exec or pods/attach access detected",
	Severity:    SeverityMedium,
	Description: "One or more ClusterRoleBindings grant 'pods/exec' or 'pods/attach' at cluster scope. This allows arbitrary command execution in any pod.",
	Remediation: "Scope pods/exec permissions to specific namespaces using RoleBindings instead of ClusterRoleBindings. Remove this permission from broad groups like 'system:authenticated'.",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, b := range info.PodExecBindings {
			subjects := access.FormatSubjects(b.Subjects)
			if subjects == "" {
				subjects = "(no subjects)"
			}
			// cluster-admin and built-in system: roles are expected to have this permission.
			if b.RoleName == "cluster-admin" || strings.HasPrefix(b.RoleName, "system:") {
				continue
			}
			scope := "cluster-scoped"
			if b.Namespace != "" {
				scope = fmt.Sprintf("namespace %s", b.Namespace)
			}
			f := &AccessFinding{
				Subject: subjects,
				Detail:  fmt.Sprintf("%s/%s (%s)", b.RoleKind, b.RoleName, scope),
				Actual:  strings.Join(b.Verbs, ",") + " on pods/exec",
				Message: fmt.Sprintf("%s '%s' grants pods/exec in %s to: %s", b.RoleKind, b.RoleName, scope, subjects),
			}
			if hasDangerousSubject(b.Subjects) {
				sev := SeverityCritical
				f.SeverityOverride = &sev
				f.Message += " [ESCALATED: broad system group can exec into any pod]"
			}
			findings = append(findings, f)
		}
		return findings
	},
}

// NV3303: pods with hostPID, hostNetwork, or hostIPC
var ruleHostPIDPods = AccessRule{
	ID:          "NV3303",
	Title:       "Privileged pods: hostPID/hostNetwork/hostIPC detected",
	Severity:    SeverityHigh,
	Description: "One or more pods use hostPID, hostNetwork, or hostIPC. These settings share the host's process/network/IPC namespace, enabling node escape attacks.",
	Remediation: "Remove hostPID/hostNetwork/hostIPC from pod specs unless absolutely required (e.g. system DaemonSets). Use PodSecurity admission to enforce restrictions.",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, pod := range info.RiskyPods {
			if !pod.HostPID && !pod.HostNetwork && !pod.HostIPC {
				continue
			}
			// System namespaces (kube-system, kube-public, kube-node-lease) routinely
			// run DaemonSets with host namespaces (kube-proxy, CNI plugins, etc.).
			// These are expected and would generate constant noise.
			if pod.IsSystemNamespace {
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
	Severity:    SeverityHigh,
	Description: "One or more pods run privileged containers or mount sensitive host paths (/etc, /var/run, /proc, etc.). These configurations allow full node filesystem access.",
	Remediation: "Remove privileged:true from container SecurityContext. Replace sensitive hostPath mounts with emptyDir or persistent volumes. Use PodSecurity admission (Restricted policy).",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, pod := range info.RiskyPods {
			if !pod.Privileged && len(pod.HostPaths) == 0 {
				continue
			}
			// System namespaces routinely run privileged DaemonSets (storage drivers,
			// monitoring agents, CNI plugins). Skip to avoid constant noise.
			if pod.IsSystemNamespace {
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

// NV3305: pod with both hostPID (or hostNetwork) and privileged=true — complete node escape
var ruleNodeEscapeChain = AccessRule{
	ID:          "NV3305",
	Title:       "Node escape chain: hostPID/hostNetwork + privileged container",
	Severity:    SeverityCritical,
	Description: "A pod combines hostPID or hostNetwork with a privileged container. This combination provides complete access to the node's process tree and filesystem, enabling a full node compromise.",
	Remediation: "Remove privileged:true and hostPID/hostNetwork from the pod spec. Use PodSecurity admission (Restricted policy) to prevent this combination cluster-wide.",
	Check: func(info *access.ClusterAccessInfo) []*AccessFinding {
		var findings []*AccessFinding
		for _, pod := range info.RiskyPods {
			if !pod.Privileged {
				continue
			}
			if !pod.HostPID && !pod.HostNetwork {
				continue
			}
			if pod.IsSystemNamespace {
				continue
			}
			var flags []string
			if pod.HostPID {
				flags = append(flags, "hostPID")
			}
			if pod.HostNetwork {
				flags = append(flags, "hostNetwork")
			}
			combo := strings.Join(flags, "+") + "+privileged"
			findings = append(findings, &AccessFinding{
				Subject: fmt.Sprintf("%s/%s", pod.Namespace, pod.PodName),
				Detail:  combo,
				Actual:  combo + "=true",
				Message: fmt.Sprintf("pod %s/%s: %s combination enables complete node compromise", pod.Namespace, pod.PodName, combo),
			})
		}
		return findings
	},
}

// AllAccessRules returns all access control rules (NV3301–NV3305).
func AllAccessRules() []AccessRule {
	all := []AccessRule{
		ruleRBACNodeProxy,
		ruleRBACPodExec,
		ruleHostPIDPods,
		rulePrivilegedPods,
		ruleNodeEscapeChain,
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
