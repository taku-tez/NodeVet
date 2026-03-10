package rules

import "github.com/NodeVet/nodevet/internal/node"

// AKS rules: NV4201–NV4202

var ruleAKSDefender = NodeRule{
	ID:          "NV4201",
	Title:       "AKS: Microsoft Defender for Containers should be enabled",
	Severity:    SeverityWarn,
	Platform:    node.PlatformAKS,
	Description: "AKS Microsoft Defender for Containers profile annotation is not present. Defender provides runtime threat detection for Kubernetes workloads.",
	Remediation: "Enable Microsoft Defender for Containers in Azure Security Center, or via: az aks update --resource-group <rg> --name <cluster> --enable-defender",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.AKS == nil {
			return nil
		}
		if n.AKS.DefenderAnnotation == "" {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "(not set)",
				Message: "Defender for Containers annotation not found; runtime threat detection may be disabled",
			}
		}
		return nil
	},
}

var ruleAKSDiskEncryption = NodeRule{
	ID:          "NV4202",
	Title:       "AKS: OS Disk should use a Disk Encryption Set",
	Severity:    SeverityWarn,
	Platform:    node.PlatformAKS,
	Description: "AKS node OS disk encryption set annotation is not present. Customer-managed key encryption for OS disks may not be configured.",
	Remediation: "Configure a Disk Encryption Set for the AKS node pool: az aks create/update --disk-encryption-set-id <des-id> ...",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.AKS == nil {
			return nil
		}
		if n.AKS.DiskEncryptionSet == "" {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "(not set)",
				Message: "Disk Encryption Set annotation not found; customer-managed key encryption may not be configured",
			}
		}
		return nil
	},
}
