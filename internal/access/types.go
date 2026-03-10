package access

// RBACBinding represents a role binding that grants dangerous permissions.
type RBACBinding struct {
	RoleKind  string // "ClusterRole" or "Role"
	RoleName  string
	Namespace string // empty for ClusterRoleBinding
	Verbs     []string
	Resources []string
	Subjects  []Subject
}

// Subject is a user, group, or ServiceAccount bound to a role.
type Subject struct {
	Kind      string // "User", "Group", "ServiceAccount"
	Name      string
	Namespace string // for ServiceAccount
}

// PodRisk represents a running pod with a dangerous security configuration.
type PodRisk struct {
	Namespace     string
	PodName       string
	ContainerName string
	HostPID       bool
	HostNetwork   bool
	HostIPC       bool
	Privileged    bool
	HostPaths     []string // sensitive hostPath mounts
}

// SensitiveHostPaths is the set of host paths that represent high-risk mounts.
var SensitiveHostPaths = []string{
	"/",
	"/etc",
	"/var/run",
	"/var/run/docker.sock",
	"/var/run/containerd/containerd.sock",
	"/proc",
	"/sys",
	"/dev",
	"/run",
}

// ClusterAccessInfo holds all collected RBAC and pod risk data.
type ClusterAccessInfo struct {
	// DangerousBindings: bindings that grant nodes/proxy or pods/exec etc.
	NodeProxyBindings []RBACBinding
	PodExecBindings   []RBACBinding
	// RiskyPods: pods with dangerous security settings
	RiskyPods []PodRisk
	// NodeAuthorizationMode: from kube-apiserver (if collected)
	NodeAuthorizationMode string
	NodeRestrictionEnabled bool
}
