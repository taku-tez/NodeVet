package node

// Platform represents the detected cloud provider.
type Platform string

const (
	PlatformGKE     Platform = "GKE"
	PlatformEKS     Platform = "EKS"
	PlatformAKS     Platform = "AKS"
	PlatformUnknown Platform = "Unknown"
)

// ConditionStatus represents a node condition state.
type ConditionStatus string

const (
	ConditionTrue    ConditionStatus = "True"
	ConditionFalse   ConditionStatus = "False"
	ConditionUnknown ConditionStatus = "Unknown"
)

// NodeCondition holds a single node condition.
type NodeCondition struct {
	Type   string
	Status ConditionStatus
}

// GKENodeInfo holds GKE-specific metadata extracted from labels/annotations.
type GKENodeInfo struct {
	NodePool               string
	IntegrityMonitoring    bool // cloud.google.com/gke-shielded-integrity-monitoring
	SecureBoot             bool // cloud.google.com/gke-secure-boot
	VTPM                   bool // cloud.google.com/gke-vtpm (if present)
	WorkloadIdentityEnabled bool // iam.gke.io/gke-metadata-server-enabled
	// Note: Binary Authorization and Node Auto-Upgrade are cluster-level settings;
	// we check for their presence via annotations when available.
	BinaryAuthorizationAnnotation string // alpha.kubernetes.io/binary-authorization
}

// EKSNodeInfo holds EKS-specific metadata.
type EKSNodeInfo struct {
	NodeGroup    string
	CapacityType string
	// IMDSv2 hop-limit is not directly visible in k8s labels;
	// we check the ec2NodeMetadataHTTPPutResponseHopLimit annotation if present.
	IMDSv2HopLimit string // eks.amazonaws.com/node-group-launch-template metadata
}

// AKSNodeInfo holds AKS-specific metadata.
type AKSNodeInfo struct {
	AgentPool string
	OSSKU     string
	// azure-defender and disk encryption are cluster-level; we check annotations.
	DefenderAnnotation string // kubernetes.azure.com/defender-profile
	DiskEncryptionSet  string // kubernetes.azure.com/disk-encryption-set
}

// NodeInfo is the normalized representation of a Kubernetes Node used by rules.
type NodeInfo struct {
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	Conditions  []NodeCondition
	Platform    Platform
	GKE         *GKENodeInfo
	EKS         *EKSNodeInfo
	AKS         *AKSNodeInfo

	// Version fields populated from node.Status.NodeInfo
	KubernetesVersion       string // e.g. "v1.29.3"
	KernelVersion           string // e.g. "5.15.0-101-generic"
	ContainerRuntimeVersion string // e.g. "containerd://1.7.9"
}

// Condition returns the status of a named condition.
func (n *NodeInfo) Condition(condType string) ConditionStatus {
	for _, c := range n.Conditions {
		if c.Type == condType {
			return c.Status
		}
	}
	return ConditionUnknown
}
