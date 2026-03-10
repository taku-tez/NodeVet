package rules

import "github.com/NodeVet/nodevet/internal/node"

// GKE rules: NV4001–NV4006

var ruleGKEIntegrityMonitoring = NodeRule{
	ID:          "NV4001",
	Title:       "GKE: Shielded Node Integrity Monitoring should be enabled",
	Severity:    SeverityCritical,
	Platform:    node.PlatformGKE,
	Description: "GKE Shielded Node Integrity Monitoring is not enabled. Runtime boot integrity of the node cannot be verified.",
	Remediation: "Enable Shielded Nodes with Integrity Monitoring in the GKE node pool: gcloud container node-pools update <pool> --cluster <cluster> --enable-integrity-monitoring",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		if !n.GKE.IntegrityMonitoring {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "false",
				Message: "Shielded Node Integrity Monitoring is disabled; boot integrity cannot be verified",
			}
		}
		return nil
	},
}

var ruleGKESecureBoot = NodeRule{
	ID:          "NV4002",
	Title:       "GKE: Secure Boot should be enabled",
	Severity:    SeverityCritical,
	Platform:    node.PlatformGKE,
	Description: "GKE Secure Boot is not enabled. The node may boot unsigned or modified OS images.",
	Remediation: "Enable Secure Boot in the GKE node pool: gcloud container node-pools update <pool> --cluster <cluster> --enable-secure-boot",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		if !n.GKE.SecureBoot {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "false",
				Message: "Secure Boot is disabled; node may boot unsigned OS images",
			}
		}
		return nil
	},
}

var ruleGKEVTPM = NodeRule{
	ID:          "NV4003",
	Title:       "GKE: vTPM should be enabled",
	Severity:    SeverityMedium,
	Platform:    node.PlatformGKE,
	Description: "GKE vTPM (Virtual Trusted Platform Module) is not enabled. Hardware-backed key storage is unavailable.",
	Remediation: "Enable vTPM in the GKE node pool (requires Shielded Nodes): recreate the node pool with --enable-shielded-nodes and vTPM enabled.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		// vTPM label may not be set even when enabled on older GKE versions;
		// only flag if the label is explicitly set to false.
		if val, ok := n.Labels["cloud.google.com/gke-vtpm"]; ok && val != "true" {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  val,
				Message: "vTPM is disabled; hardware-backed key storage unavailable",
			}
		}
		return nil
	},
}

var ruleGKEWorkloadIdentity = NodeRule{
	ID:          "NV4004",
	Title:       "GKE: Workload Identity should be enabled",
	Severity:    SeverityMedium,
	Platform:    node.PlatformGKE,
	Description: "GKE Workload Identity metadata server is not enabled on this node. Pods may use the legacy metadata server, which leaks node service account credentials.",
	Remediation: "Enable Workload Identity on the node pool: gcloud container node-pools update <pool> --cluster <cluster> --workload-metadata=GKE_METADATA",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		if !n.GKE.WorkloadIdentityEnabled {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "false",
				Message: "Workload Identity metadata server not enabled; node SA credentials exposed to pods",
			}
		}
		return nil
	},
}

var ruleGKENodeAutoUpgrade = NodeRule{
	ID:          "NV4005",
	Title:       "GKE: Node Auto-Upgrade should be enabled",
	Severity:    SeverityMedium,
	Platform:    node.PlatformGKE,
	Description: "Unable to confirm GKE Node Auto-Upgrade status from node labels. Auto-Upgrade is a cluster-level setting—verify it is enabled to ensure nodes receive security patches.",
	Remediation: "Enable Node Auto-Upgrade: gcloud container node-pools update <pool> --cluster <cluster> --enable-autoupgrade",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		// Node Auto-Upgrade is a cluster-level setting; flag as informational.
		// Label cloud.google.com/gke-nodepool presence indicates GKE but not upgrade policy.
		// We emit a WARN prompting manual verification.
		if _, ok := n.Labels["cloud.google.com/gke-nodepool"]; ok {
			// Only emit once if we can detect it's definitely disabled via annotation.
			if val := n.Annotations["cloud.google.com/gke-autoupgrade"]; val == "false" {
				return &NodeFinding{
					Node:    n.Name,
					Actual:  "false",
					Message: "Node Auto-Upgrade is disabled; nodes will not receive automatic security patches",
				}
			}
		}
		return nil
	},
}

var ruleGKEBinaryAuthorization = NodeRule{
	ID:          "NV4006",
	Title:       "GKE: Binary Authorization should be enforced",
	Severity:    SeverityMedium,
	Platform:    node.PlatformGKE,
	Description: "Binary Authorization enforcement cannot be confirmed from node labels. Binary Authorization is a cluster-level policy—verify it is enabled to ensure only trusted images run.",
	Remediation: "Enable Binary Authorization in the GKE cluster settings or via: gcloud container clusters update <cluster> --binauthz-evaluation-mode=PROJECT_SINGLETON_POLICY_ENFORCE",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.GKE == nil {
			return nil
		}
		if val := n.Annotations["alpha.kubernetes.io/binary-authorization"]; val == "disabled" {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "disabled",
				Message: "Binary Authorization is disabled; untrusted container images may run",
			}
		}
		return nil
	},
}
