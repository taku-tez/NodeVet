package source

import (
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// containerdCRIPlugin is the key for the CRI plugin in containerd config.
const containerdCRIPlugin = "io.containerd.grpc.v1.cri"

// ContainerdSource reads a containerd config.toml file.
type ContainerdSource struct {
	path string
}

// NewContainerdSource creates a ContainerdSource from a file path.
func NewContainerdSource(path string) *ContainerdSource {
	return &ContainerdSource{path: path}
}

func (s *ContainerdSource) SourceName() string { return fmt.Sprintf("containerd:%s", s.path) }

func (s *ContainerdSource) Load() (map[string]string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("reading containerd config %s: %w", s.path, err)
	}
	return ParseContainerdConfig(data)
}

// containerdConfig is used to decode the top-level containerd TOML structure.
type containerdConfig struct {
	Root    string                            `toml:"root"`
	Plugins map[string]map[string]interface{} `toml:"plugins"`
}

// ParseContainerdConfig parses a containerd config.toml and returns a flat flag map.
// Keys use the prefix "runtime." followed by a canonical name.
func ParseContainerdConfig(data []byte) (map[string]string, error) {
	var cfg containerdConfig
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing containerd config.toml: %w", err)
	}

	result := make(map[string]string)

	// Extract root path (to detect rootless mode)
	if cfg.Root != "" {
		result["runtime.root"] = cfg.Root
	}

	// Extract CRI plugin settings
	cri, ok := cfg.Plugins[containerdCRIPlugin]
	if !ok {
		return result, nil
	}

	extractBool(result, cri, "enable_unprivileged_ports", "runtime.enable-unprivileged-ports")
	extractBool(result, cri, "enable_unprivileged_icmp", "runtime.enable-unprivileged-icmp")
	extractBool(result, cri, "restrict_oci_annotations", "runtime.restrict-oci-annotations")

	// Containerd nested section
	if containerdSec, ok := toMap(cri["containerd"]); ok {
		if s, ok := containerdSec["snapshotter"].(string); ok {
			result["runtime.snapshotter"] = s
		}
		// Default runtime seccomp/AppArmor
		if runtimes, ok := toMap(containerdSec["runtimes"]); ok {
			if runc, ok := toMap(runtimes["runc"]); ok {
				if opts, ok := toMap(runc["options"]); ok {
					extractString(result, opts, "SystemdCgroup", "runtime.runc.systemd-cgroup")
				}
			}
		}
		// Default runtime handler seccomp profile
		if defRuntime, ok := toMap(containerdSec["default_runtime"]); ok {
			if opts, ok := toMap(defRuntime["options"]); ok {
				extractString(result, opts, "SeccompProfile", "runtime.seccomp-profile")
			}
		}
	}

	// Registry mirrors — collect all endpoint URLs
	if regSec, ok := toMap(cri["registry"]); ok {
		if mirrors, ok := toMap(regSec["mirrors"]); ok {
			var allEndpoints []string
			var insecureEndpoints []string
			for _, v := range mirrors {
				if mirrorMap, ok := toMap(v); ok {
					if endpoints, ok := mirrorMap["endpoint"].([]interface{}); ok {
						for _, ep := range endpoints {
							if epStr, ok := ep.(string); ok {
								allEndpoints = append(allEndpoints, epStr)
								if strings.HasPrefix(epStr, "http://") {
									insecureEndpoints = append(insecureEndpoints, epStr)
								}
							}
						}
					}
				}
			}
			if len(allEndpoints) > 0 {
				result["runtime.registry-mirrors"] = strings.Join(allEndpoints, ",")
			}
			if len(insecureEndpoints) > 0 {
				result["runtime.insecure-registry-mirrors"] = strings.Join(insecureEndpoints, ",")
			}
		}
	}

	return result, nil
}

func extractBool(result map[string]string, m map[string]interface{}, key, flagName string) {
	if v, ok := m[key]; ok {
		switch b := v.(type) {
		case bool:
			if b {
				result[flagName] = "true"
			} else {
				result[flagName] = "false"
			}
		}
	}
}

func extractString(result map[string]string, m map[string]interface{}, key, flagName string) {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			result[flagName] = s
		}
	}
}

func toMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}
