package rules

import "github.com/NodeVet/nodevet/internal/node"

// AllNodeRules returns all registered node-level rules.
func AllNodeRules() []NodeRule {
	all := []NodeRule{
		// Node Conditions (NV3001–NV3003)
		ruleNodeReady,
		ruleNodeMemoryPressure,
		ruleNodeDiskPressure,
		// Version staleness (NV7001–NV7003)
		ruleK8sVersionStaleness,
		ruleContainerdCVE,
		ruleKernelCVE,
		// GKE (NV4001–NV4006)
		ruleGKEIntegrityMonitoring,
		ruleGKESecureBoot,
		ruleGKEVTPM,
		ruleGKEWorkloadIdentity,
		ruleGKENodeAutoUpgrade,
		ruleGKEBinaryAuthorization,
		// EKS (NV4101–NV4103)
		ruleEKSIMDSv2,
		ruleEKSEBSEncryption,
		ruleEKSAMIAutoUpdate,
		// AKS (NV4201–NV4202)
		ruleAKSDefender,
		ruleAKSDiskEncryption,
		// SSH / OS access (NV3201–NV3202)
		ruleGKEOSLogin,
		ruleGKEDirectSSH,
	}

	// Back-fill Rule pointer on each Finding.
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
