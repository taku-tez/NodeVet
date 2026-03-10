package rules

import "github.com/NodeVet/nodevet/internal/ebpf"

// AllEBPFRules returns all eBPF/runtime security rules (NV6001–NV6202).
func AllEBPFRules() []EBPFRule {
	all := []EBPFRule{
		ruleFalcoDeployed,
		ruleFalcoCriticalRules,
		ruleFalcoOutput,
		ruleTetragonDeployed,
		ruleTetragonPrivilegedOps,
		ruleCiliumHubble,
		ruleCiliumL7Proxy,
	}
	for i := range all {
		r := &all[i]
		orig := r.Check
		r.Check = func(info *ebpf.EBPFClusterInfo) *EBPFFinding {
			f := orig(info)
			if f != nil {
				f.Rule = r
			}
			return f
		}
	}
	return all
}
