package node

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// FromK8sNode converts a Kubernetes Node object into NodeInfo.
func FromK8sNode(n corev1.Node) *NodeInfo {
	info := &NodeInfo{
		Name:        n.Name,
		Labels:      n.Labels,
		Annotations: n.Annotations,
	}
	if info.Labels == nil {
		info.Labels = map[string]string{}
	}
	if info.Annotations == nil {
		info.Annotations = map[string]string{}
	}

	// Extract conditions
	for _, c := range n.Status.Conditions {
		info.Conditions = append(info.Conditions, NodeCondition{
			Type:   string(c.Type),
			Status: ConditionStatus(c.Status),
		})
	}

	// Version info from node status
	info.KubernetesVersion = n.Status.NodeInfo.KubeletVersion
	info.KernelVersion = n.Status.NodeInfo.KernelVersion
	info.ContainerRuntimeVersion = n.Status.NodeInfo.ContainerRuntimeVersion

	// Detect platform and extract provider-specific info
	info.Platform = detectPlatform(info.Labels)
	switch info.Platform {
	case PlatformGKE:
		info.GKE = extractGKEInfo(info.Labels, info.Annotations)
	case PlatformEKS:
		info.EKS = extractEKSInfo(info.Labels, info.Annotations)
	case PlatformAKS:
		info.AKS = extractAKSInfo(info.Labels, info.Annotations)
	}

	return info
}

func detectPlatform(labels map[string]string) Platform {
	for k := range labels {
		switch {
		case strings.HasPrefix(k, "cloud.google.com/") ||
			strings.HasPrefix(k, "iam.gke.io/") ||
			k == "node.gke.io/os-distribution":
			return PlatformGKE
		case strings.HasPrefix(k, "eks.amazonaws.com/") ||
			k == "alpha.eksctl.io/cluster-name":
			return PlatformEKS
		case strings.HasPrefix(k, "kubernetes.azure.com/") ||
			k == "agentpool":
			return PlatformAKS
		}
	}
	return PlatformUnknown
}

func extractGKEInfo(labels, annotations map[string]string) *GKENodeInfo {
	info := &GKENodeInfo{
		NodePool: labels["cloud.google.com/gke-nodepool"],
	}
	info.IntegrityMonitoring = labels["cloud.google.com/gke-shielded-integrity-monitoring"] == "true"
	info.SecureBoot = labels["cloud.google.com/gke-secure-boot"] == "true"
	info.VTPM = labels["cloud.google.com/gke-vtpm"] == "true"
	info.WorkloadIdentityEnabled = labels["iam.gke.io/gke-metadata-server-enabled"] == "true"
	info.BinaryAuthorizationAnnotation = annotations["alpha.kubernetes.io/binary-authorization"]
	return info
}

func extractEKSInfo(labels, annotations map[string]string) *EKSNodeInfo {
	return &EKSNodeInfo{
		NodeGroup:      labels["eks.amazonaws.com/nodegroup"],
		CapacityType:   labels["eks.amazonaws.com/capacityType"],
		IMDSv2HopLimit: annotations["eks.amazonaws.com/compute-type"],
	}
}

func extractAKSInfo(labels, annotations map[string]string) *AKSNodeInfo {
	return &AKSNodeInfo{
		AgentPool:          labels["kubernetes.azure.com/agentpool"],
		OSSKU:              labels["kubernetes.azure.com/os-sku"],
		DefenderAnnotation: annotations["kubernetes.azure.com/defender-profile"],
		DiskEncryptionSet:  annotations["kubernetes.azure.com/disk-encryption-set"],
	}
}
