package source

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/transport"
)

// ConfigzSource fetches kubelet configuration from the live API server.
type ConfigzSource struct {
	nodeName       string
	kubeconfigPath string
}

// NewConfigzSource creates a ConfigzSource for a specific node.
func NewConfigzSource(nodeName, kubeconfigPath string) *ConfigzSource {
	return &ConfigzSource{
		nodeName:       nodeName,
		kubeconfigPath: kubeconfigPath,
	}
}

func (s *ConfigzSource) SourceName() string {
	return fmt.Sprintf("configz:%s", s.nodeName)
}

func (s *ConfigzSource) Load() (map[string]string, error) {
	cfg, err := clientcmd.BuildConfigFromFlags("", s.kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("loading kubeconfig: %w", err)
	}

	transportCfg, err := cfg.TransportConfig()
	if err != nil {
		return nil, fmt.Errorf("building transport config: %w", err)
	}
	rt, err := transport.New(transportCfg)
	if err != nil {
		return nil, fmt.Errorf("building HTTP transport: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/nodes/%s/proxy/configz", cfg.Host, s.nodeName)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.BearerToken)
	}

	client := &http.Client{Transport: rt}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	return parseConfigzJSON(body)
}

// parseConfigzJSON parses the /configz JSON response.
func parseConfigzJSON(data []byte) (map[string]string, error) {
	var wrapper struct {
		KubeletConfig map[string]interface{} `json:"kubeletconfig"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing configz JSON: %w", err)
	}

	flat := flattenMap("", wrapper.KubeletConfig)
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
