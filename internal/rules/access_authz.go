package rules

import "strings"

// kube-apiserver authorization rules: NV3101, NV3102
// These reuse the existing Rule + ConfigSource infrastructure
// (FlagSource or YAMLSource pointed at kube-apiserver config).

// NV3101: authorization-mode must include Node
var ruleAPIServerNodeAuthorizer = Rule{
	ID:          "NV3101",
	Title:       "kube-apiserver: Node Authorizer must be enabled",
	Severity:    SeverityError,
	Description: "kube-apiserver authorization-mode does not include 'Node'. Without the Node Authorizer, kubelets can read any secret in the cluster, not just those for their own pods.",
	Remediation: "Add 'Node' to --authorization-mode in kube-apiserver configuration: --authorization-mode=Node,RBAC",
	Check: func(values map[string]string) *Finding {
		mode := values["authorization-mode"]
		if mode == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "authorization-mode is not set; Node Authorizer may not be active",
			}
		}
		for _, m := range strings.Split(mode, ",") {
			if strings.TrimSpace(m) == "Node" {
				return nil
			}
		}
		return &Finding{
			Actual:  mode,
			Message: "authorization-mode does not include 'Node'; kubelets have unrestricted API access",
		}
	},
}

// NV3102: NodeRestriction admission plugin must be enabled
var ruleAPIServerNodeRestriction = Rule{
	ID:          "NV3102",
	Title:       "kube-apiserver: NodeRestriction admission plugin must be enabled",
	Severity:    SeverityError,
	Description: "kube-apiserver NodeRestriction admission plugin is not enabled. Kubelets can modify any node or pod object, not just their own.",
	Remediation: "Add 'NodeRestriction' to --enable-admission-plugins in kube-apiserver configuration.",
	Check: func(values map[string]string) *Finding {
		plugins := values["enable-admission-plugins"]
		if plugins == "" {
			return &Finding{
				Actual:  "(not set)",
				Message: "enable-admission-plugins is not set; NodeRestriction may not be active",
			}
		}
		for _, p := range strings.Split(plugins, ",") {
			if strings.TrimSpace(p) == "NodeRestriction" {
				return nil
			}
		}
		return &Finding{
			Actual:  plugins,
			Message: "enable-admission-plugins does not include NodeRestriction; kubelets can modify any node/pod object",
		}
	},
}

// AllAPIServerRules returns kube-apiserver security rules (NV3101–NV3102).
func AllAPIServerRules() []Rule {
	all := []Rule{
		ruleAPIServerNodeAuthorizer,
		ruleAPIServerNodeRestriction,
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
