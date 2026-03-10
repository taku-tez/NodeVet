package ebpf

// FalcoRulesFile represents a parsed Falco rules ConfigMap.
type FalcoRulesFile struct {
	Name            string
	DisabledCritical []string // rule names with override.enabled=false
}

// FalcoInfo holds the collected state of a Falco deployment.
type FalcoInfo struct {
	Deployed      bool
	Version       string
	RulesFiles    []FalcoRulesFile
	OutputWebhook bool // HTTP webhook or gRPC output configured
}

// TetragonInfo holds the collected state of a Tetragon deployment.
type TetragonInfo struct {
	Deployed        bool
	TracingPolicies []string // names of TracingPolicy CRs found
	HasPrivilegedOp bool     // at least one policy covers privileged operations
}

// CiliumInfo holds the collected state of a Cilium deployment.
type CiliumInfo struct {
	Deployed       bool
	HubbleEnabled  bool
	L7ProxyEnabled bool
}

// EBPFClusterInfo aggregates eBPF/runtime security tool state for the cluster.
type EBPFClusterInfo struct {
	Falco    FalcoInfo
	Tetragon TetragonInfo
	Cilium   CiliumInfo
}
