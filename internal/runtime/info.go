package runtime

// RuntimeClassInfo holds information about a Kubernetes RuntimeClass object.
type RuntimeClassInfo struct {
	Name    string
	Handler string // runtimeHandler (e.g. "runsc" for gVisor, "kata" for Kata Containers)
	// Overhead is omitted for v0.3.0
}

// KnownSandboxedHandlers is the set of runtimeHandlers that provide
// hardware-level or kernel-level isolation (sandboxed runtimes).
var KnownSandboxedHandlers = map[string]string{
	"runsc":          "gVisor",
	"kata":           "Kata Containers",
	"kata-qemu":      "Kata Containers (QEMU)",
	"kata-clh":       "Kata Containers (Cloud Hypervisor)",
	"kata-fc":        "Kata Containers (Firecracker)",
	"kata-remote":    "Kata Containers (Remote)",
	"io.containerd.kata.v2": "Kata Containers",
}

// ClusterRuntimeInfo holds all RuntimeClass objects in the cluster.
type ClusterRuntimeInfo struct {
	RuntimeClasses []RuntimeClassInfo
}

// HasSandboxedRuntime returns true if any RuntimeClass uses a known sandboxed handler.
func (c *ClusterRuntimeInfo) HasSandboxedRuntime() bool {
	for _, rc := range c.RuntimeClasses {
		if _, ok := KnownSandboxedHandlers[rc.Handler]; ok {
			return true
		}
	}
	return false
}

// SandboxedRuntimes returns the list of sandboxed RuntimeClasses.
func (c *ClusterRuntimeInfo) SandboxedRuntimes() []RuntimeClassInfo {
	var result []RuntimeClassInfo
	for _, rc := range c.RuntimeClasses {
		if _, ok := KnownSandboxedHandlers[rc.Handler]; ok {
			result = append(result, rc)
		}
	}
	return result
}
