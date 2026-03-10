package rules

import "github.com/NodeVet/nodevet/internal/node"

// EKS rules: NV4101–NV4103

var ruleEKSIMDSv2 = NodeRule{
	ID:          "NV4101",
	Title:       "EKS: IMDSv2 should be enforced (hop-limit=1)",
	Severity:    SeverityError,
	Platform:    node.PlatformEKS,
	Description: "EKS IMDSv2 enforcement cannot be confirmed from node labels. IMDSv2 with hop-limit=1 prevents containers from accessing the EC2 instance metadata endpoint.",
	Remediation: "Enforce IMDSv2 in the EKS managed node group launch template: set HttpPutResponseHopLimit=1 and HttpTokens=required. Or use eksctl: eksctl set nodegroup --cluster <cluster> --name <ng> --managed metadata-api-token=required",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.EKS == nil {
			return nil
		}
		// Check annotation set by node-level tools like eks-node-viewer or custom admission.
		if val := n.Annotations["eks.amazonaws.com/imds-token-required"]; val == "false" {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "false",
				Message: "IMDSv2 not enforced; containers may access EC2 instance metadata",
			}
		}
		return nil
	},
}

var ruleEKSEBSEncryption = NodeRule{
	ID:          "NV4102",
	Title:       "EKS: EBS volumes should be encrypted",
	Severity:    SeverityWarn,
	Platform:    node.PlatformEKS,
	Description: "EKS node EBS volume encryption cannot be confirmed from node labels. Unencrypted node volumes may expose data at rest.",
	Remediation: "Enable EBS encryption by default in the AWS account, or specify encrypted volumes in the EKS managed node group launch template.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.EKS == nil {
			return nil
		}
		if val := n.Annotations["eks.amazonaws.com/ebs-encrypted"]; val == "false" {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "false",
				Message: "EBS volume is not encrypted; data at rest may be exposed",
			}
		}
		return nil
	},
}

var ruleEKSAMIAutoUpdate = NodeRule{
	ID:          "NV4103",
	Title:       "EKS: Managed Node Group should have Auto-Update enabled",
	Severity:    SeverityWarn,
	Platform:    node.PlatformEKS,
	Description: "EKS managed node group auto-update policy cannot be confirmed from node labels. Nodes should be kept up-to-date with the latest Amazon EKS optimized AMI.",
	Remediation: "Configure the managed node group update policy to DEFAULT or FORCE_NEW_UPDATE: aws eks update-nodegroup-config --cluster-name <cluster> --nodegroup-name <ng> --update-config maxUnavailable=1",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.EKS == nil {
			return nil
		}
		// eks.amazonaws.com/release-version label is set when AMI version is tracked.
		// If absent, we cannot confirm auto-update is configured.
		if _, ok := n.Labels["eks.amazonaws.com/release-version"]; !ok {
			return &NodeFinding{
				Node:    n.Name,
				Actual:  "(label not found)",
				Message: "eks.amazonaws.com/release-version label missing; AMI tracking and auto-update may not be configured",
			}
		}
		return nil
	},
}
