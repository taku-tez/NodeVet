package source

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// fieldMap maps KubeletConfiguration YAML field paths (dot-notation) to canonical flag names.
var fieldMap = map[string]string{
	"authentication.anonymous.enabled":  "anonymous-auth",
	"authentication.x509.clientCAFile": "client-ca-file",
	"authorization.mode":               "authorization-mode",
	"tlsCertFile":                      "tls-cert-file",
	"tlsPrivateKeyFile":                "tls-private-key-file",
	"tlsCipherSuites":                  "tls-cipher-suites",
	"rotateCertificates":               "rotate-certificates",
	"serverTLSBootstrap":               "rotate-server-certificates",
	"protectKernelDefaults":            "protect-kernel-defaults",
	"makeIPTablesUtilChains":           "make-iptables-util-chains",
	"eventRecordQPS":                   "event-qps",
	"streamingConnectionIdleTimeout":   "streaming-connection-idle-timeout",
	"readOnlyPort":                     "read-only-port",
}

// YAMLSource reads a KubeletConfiguration YAML file.
type YAMLSource struct {
	path string
}

// NewYAMLSource creates a YAMLSource from a file path.
func NewYAMLSource(path string) *YAMLSource {
	return &YAMLSource{path: path}
}

func (s *YAMLSource) SourceName() string { return fmt.Sprintf("yaml:%s", s.path) }

func (s *YAMLSource) Load() (map[string]string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("reading kubelet config %s: %w", s.path, err)
	}
	return ParseKubeletConfigYAML(data)
}

// ParseKubeletConfigYAML parses a KubeletConfiguration YAML and returns a flat flag map.
func ParseKubeletConfigYAML(data []byte) (map[string]string, error) {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing kubelet config YAML: %w", err)
	}

	flat := flattenMap("", raw)
	result := make(map[string]string)

	for dotKey, val := range flat {
		flagName, ok := fieldMap[dotKey]
		if !ok {
			continue
		}
		result[flagName] = formatValue(val)
	}
	return result, nil
}

// flattenMap recursively flattens a nested map into dot-notation keys.
func flattenMap(prefix string, m map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for k, v := range m {
		fullKey := k
		if prefix != "" {
			fullKey = prefix + "." + k
		}
		switch child := v.(type) {
		case map[string]interface{}:
			for ck, cv := range flattenMap(fullKey, child) {
				result[ck] = cv
			}
		default:
			result[fullKey] = v
		}
	}
	return result
}

// formatValue converts an interface{} to a string representation.
func formatValue(v interface{}) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case int, int64, float64:
		return fmt.Sprintf("%v", val)
	case []interface{}:
		// For cipher suites: join with comma
		var parts []string
		for _, item := range val {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", val)
	}
}
