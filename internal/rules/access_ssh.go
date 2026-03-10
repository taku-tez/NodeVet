package rules

import "github.com/NodeVet/nodevet/internal/node"

// SSH / OS access rules on nodes: NV3201–NV3202

// NV3201: GKE OS Login should be enabled
var ruleGKEOSLogin = NodeRule{
	ID:          "NV3201",
	Title:       "GKE: OS Login should be enabled",
	Severity:    SeverityWarn,
	Platform:    node.PlatformGKE,
	Description: "GKE OS Login is not enabled on this node. Without OS Login, SSH access uses project-wide SSH keys, which are harder to audit and revoke.",
	Remediation: "Enable OS Login on the GKE node pool: gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE. Or set the label on the node pool.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		// OS Login is indicated by label cloud.google.com/os-login or metadata
		if val := n.Labels["cloud.google.com/gke-os-login"]; val != "true" {
			actual := val
			if actual == "" {
				actual = "false (not set)"
			}
			return &NodeFinding{
				Node:    n.Name,
				Actual:  actual,
				Message: "OS Login is not enabled; SSH access uses project-wide keys (harder to audit/revoke)",
			}
		}
		return nil
	},
}

// NV3202: GKE nodes should not allow direct SSH via external firewall rules
// (detected via absence of IAP tunnel annotation or presence of 0.0.0.0/0 SSH)
var ruleGKEDirectSSH = NodeRule{
	ID:          "NV3202",
	Title:       "GKE: direct SSH access (0.0.0.0/0) should be restricted",
	Severity:    SeverityWarn,
	Platform:    node.PlatformGKE,
	Description: "GKE node does not show evidence of IAP-tunneled SSH access. Direct SSH access from the internet exposes nodes to brute-force and exploitation.",
	Remediation: "Restrict SSH firewall rules to internal ranges only and use IAP for SSH access: gcloud compute firewall-rules update <rule> --source-ranges 35.235.240.0/20",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		// If IAP annotation is present and set to "true", access is via IAP tunnel
		if val := n.Annotations["cloud.google.com/iap-tunnel-enabled"]; val == "true" {
			return nil
		}
		// Check for explicit firewall annotation allowing 0.0.0.0/0 SSH
		if val := n.Annotations["cloud.google.com/ssh-open-to-internet"]; val == "true" {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "open",
				Message: "SSH is accessible from the internet (0.0.0.0/0); use IAP tunnel instead",
			}
		}
		return nil
	},
}

// AddSSHNodeRules appends SSH/OS access node rules to AllNodeRules.
// These are registered separately to keep the node_registry clean.
func SSHNodeRules() []NodeRule {
	all := []NodeRule{
		ruleGKEOSLogin,
		ruleGKEDirectSSH,
	}
	for i := range all {
		r := &all[i]
		orig := r.Check
		r.Check = func(n *node.NodeInfo) *NodeFinding {
			f := orig(n)
			if f != nil {
				f.Rule = r
			}
			return f
		}
	}
	return all
}
