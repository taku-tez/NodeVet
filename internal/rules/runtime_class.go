package rules

import (
	"fmt"
	"strings"

	"github.com/NodeVet/nodevet/internal/runtime"
)

// RuntimeClassRule describes a check on cluster RuntimeClass objects.
type RuntimeClassRule struct {
	ID          string
	Title       string
	Severity    Severity
	Description string
	Remediation string
	Check       func(info *runtime.ClusterRuntimeInfo) *RuntimeClassFinding
}

// RuntimeClassFinding is produced when a RuntimeClassRule detects a problem.
type RuntimeClassFinding struct {
	Rule    *RuntimeClassRule
	Actual  string
	Message string
}

// RuntimeClassResult holds findings for RuntimeClass checks.
type RuntimeClassResult struct {
	Findings []*RuntimeClassFinding
	Passed   int
	Errors   int
	Warnings int
}

// NV2101: at least one sandboxed runtime should be available
var ruleRuntimeClassSandboxed = RuntimeClassRule{
	ID:          "NV2101",
	Title:       "RuntimeClass: sandboxed runtime (gVisor/Kata) should be available",
	Severity:    SeverityMedium,
	Description: "No sandboxed RuntimeClass (gVisor, Kata Containers) is defined in the cluster. High-risk workloads cannot use hardware-level isolation.",
	Remediation: "Install gVisor (runsc) or Kata Containers and create a RuntimeClass: kubectl apply -f runtimeclass-gvisor.yaml. See: https://gvisor.dev/docs/user_guide/containerd/",
	Check: func(info *runtime.ClusterRuntimeInfo) *RuntimeClassFinding {
		if !info.HasSandboxedRuntime() {
			handlers := make([]string, 0, len(info.RuntimeClasses))
			for _, rc := range info.RuntimeClasses {
				handlers = append(handlers, fmt.Sprintf("%s(%s)", rc.Name, rc.Handler))
			}
			actual := "(none)"
			if len(handlers) > 0 {
				actual = strings.Join(handlers, ", ")
			}
			return &RuntimeClassFinding{
				Actual:  actual,
				Message: "no sandboxed RuntimeClass (gVisor/Kata) found; high-risk workloads lack hardware isolation",
			}
		}
		return nil
	},
}

// NV2102: all RuntimeClass handlers must be non-empty
var ruleRuntimeClassHandlerValid = RuntimeClassRule{
	ID:          "NV2102",
	Title:       "RuntimeClass: runtimeHandler must not be empty",
	Severity:    SeverityHigh,
	Description: "One or more RuntimeClass objects have an empty runtimeHandler. This may cause pods using the RuntimeClass to fail to schedule or use the default (potentially insecure) runtime.",
	Remediation: "Ensure every RuntimeClass has a valid runtimeHandler that corresponds to a configured CRI runtime (e.g. 'runc', 'runsc', 'kata').",
	Check: func(info *runtime.ClusterRuntimeInfo) *RuntimeClassFinding {
		var invalid []string
		for _, rc := range info.RuntimeClasses {
			if strings.TrimSpace(rc.Handler) == "" {
				invalid = append(invalid, rc.Name)
			}
		}
		if len(invalid) > 0 {
			return &RuntimeClassFinding{
				Actual:  strings.Join(invalid, ", "),
				Message: "RuntimeClass objects with empty runtimeHandler: " + strings.Join(invalid, ", "),
			}
		}
		return nil
	},
}

// AllRuntimeClassRules returns all RuntimeClass rules.
func AllRuntimeClassRules() []RuntimeClassRule {
	all := []RuntimeClassRule{
		ruleRuntimeClassSandboxed,
		ruleRuntimeClassHandlerValid,
	}
	for i := range all {
		r := &all[i]
		orig := r.Check
		r.Check = func(info *runtime.ClusterRuntimeInfo) *RuntimeClassFinding {
			f := orig(info)
			if f != nil {
				f.Rule = r
			}
			return f
		}
	}
	return all
}
