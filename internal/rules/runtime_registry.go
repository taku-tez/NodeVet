package rules

// AllRuntimeRules returns all containerd/runtime rules (NV2xxx).
func AllRuntimeRules() []Rule {
	all := []Rule{
		ruleContainerdUnprivilegedPorts,
		ruleContainerdUnprivilegedICMP,
		ruleContainerdSnapshotter,
		ruleContainerdInsecureRegistryMirrors,
		ruleContainerdRestrictOCIAnnotations,
		ruleContainerdSeccompProfile,
		ruleContainerdRootless,
	}
	for i := range all {
		r := &all[i]
		orig := r.Check
		r.Check = func(values map[string]string) *Finding {
			f := orig(values)
			if f != nil {
				f.Rule = r
			}
			return f
		}
	}
	return all
}
