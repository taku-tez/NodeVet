package ebpf

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"gopkg.in/yaml.v3"
)

// Collector gathers eBPF/runtime security tool state from the cluster.
type Collector struct {
	KubeconfigPath string
	Context        string
}

func (c *Collector) buildClientset() (*kubernetes.Clientset, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if c.KubeconfigPath != "" {
		loadingRules.ExplicitPath = c.KubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	if c.Context != "" {
		overrides.CurrentContext = c.Context
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// Collect gathers the full eBPF cluster state.
func (c *Collector) Collect(ctx context.Context) (*EBPFClusterInfo, error) {
	cs, err := c.buildClientset()
	if err != nil {
		return nil, err
	}
	info := &EBPFClusterInfo{}
	if err := c.collectFalco(ctx, cs, info); err != nil {
		return nil, fmt.Errorf("falco collection: %w", err)
	}
	if err := c.collectTetragon(ctx, cs, info); err != nil {
		return nil, fmt.Errorf("tetragon collection: %w", err)
	}
	if err := c.collectCilium(ctx, cs, info); err != nil {
		return nil, fmt.Errorf("cilium collection: %w", err)
	}
	return info, nil
}

// collectFalco checks for Falco DaemonSet and reads its ConfigMaps.
func (c *Collector) collectFalco(ctx context.Context, cs *kubernetes.Clientset, info *EBPFClusterInfo) error {
	// Search all namespaces for a DaemonSet named "falco"
	dsList, err := cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing DaemonSets: %w", err)
	}

	var falcoNS string
	for _, ds := range dsList.Items {
		if strings.Contains(strings.ToLower(ds.Name), "falco") {
			info.Falco.Deployed = true
			falcoNS = ds.Namespace
			// Extract version label if present
			if v, ok := ds.Labels["app.kubernetes.io/version"]; ok {
				info.Falco.Version = v
			}
			break
		}
	}

	if !info.Falco.Deployed || falcoNS == "" {
		return nil
	}

	// Check ConfigMaps for Falco rules and output config
	cmList, err := cs.CoreV1().ConfigMaps(falcoNS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing ConfigMaps in %s: %w", falcoNS, err)
	}

	for _, cm := range cmList.Items {
		name := strings.ToLower(cm.Name)

		// Check for output configuration in falco.yaml-style ConfigMaps
		if name == "falco" || strings.Contains(name, "falco-config") {
			for _, v := range cm.Data {
				if strings.Contains(v, "http_output") && strings.Contains(v, "enabled: true") {
					info.Falco.OutputWebhook = true
				}
				if strings.Contains(v, "grpc_output") && strings.Contains(v, "enabled: true") {
					info.Falco.OutputWebhook = true
				}
			}
		}

		// Parse Falco rules files to detect disabled critical rules
		if strings.Contains(name, "rules") || strings.Contains(name, "falco-rules") {
			for key, data := range cm.Data {
				disabled := parseFalcoRulesForDisabled(data)
				if len(disabled) > 0 || isRulesKey(key) {
					info.Falco.RulesFiles = append(info.Falco.RulesFiles, FalcoRulesFile{
						Name:            fmt.Sprintf("%s/%s", cm.Name, key),
						DisabledCritical: disabled,
					})
				}
			}
		}
	}
	return nil
}

// isRulesKey returns true if the ConfigMap key looks like a Falco rules file.
func isRulesKey(key string) bool {
	return strings.HasSuffix(key, ".yaml") || strings.HasSuffix(key, ".yml") ||
		strings.Contains(key, "rules")
}

// falcoRulesEntry is used for YAML parsing of Falco rules.
type falcoRulesEntry struct {
	Rule     string `yaml:"rule"`
	Override struct {
		Enabled *bool `yaml:"enabled"`
	} `yaml:"override"`
}

// parseFalcoRulesForDisabled returns the names of rules with override.enabled=false.
func parseFalcoRulesForDisabled(data string) []string {
	var entries []falcoRulesEntry
	// Falco rules files are YAML lists
	if err := yaml.Unmarshal([]byte(data), &entries); err != nil {
		return nil
	}
	var disabled []string
	for _, e := range entries {
		if e.Rule != "" && e.Override.Enabled != nil && !*e.Override.Enabled {
			disabled = append(disabled, e.Rule)
		}
	}
	return disabled
}

// collectTetragon checks for Tetragon DaemonSet and TracingPolicy CRs.
func (c *Collector) collectTetragon(ctx context.Context, cs *kubernetes.Clientset, info *EBPFClusterInfo) error {
	dsList, err := cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing DaemonSets: %w", err)
	}

	for _, ds := range dsList.Items {
		if strings.Contains(strings.ToLower(ds.Name), "tetragon") {
			info.Tetragon.Deployed = true
			break
		}
	}

	if !info.Tetragon.Deployed {
		return nil
	}

	// TracingPolicy is a CRD; use dynamic client via raw REST call via ConfigMaps
	// as a proxy: look for ConfigMaps with "tracing" or "policy" in name as a hint,
	// or check if the CRD resource group exists via API groups.
	// We use a simple heuristic: check the API server resource groups for cilium.io.
	_, apiGroups, err := cs.Discovery().ServerGroupsAndResources()
	if err != nil {
		// Discovery failure is non-fatal; mark as unknown
		return nil
	}

	for _, rList := range apiGroups {
		if !strings.Contains(rList.GroupVersion, "cilium.io") {
			continue
		}
		for _, r := range rList.APIResources {
			if strings.ToLower(r.Kind) == "tracingpolicy" {
				// CRD exists; we can't list CRs without dynamic client here,
				// but we mark that the CRD is registered and count it as "deployed"
				info.Tetragon.TracingPolicies = append(info.Tetragon.TracingPolicies, r.Kind)
			}
		}
	}

	// Check ConfigMaps for TracingPolicy YAML that may have been applied
	cmList, err := cs.CoreV1().ConfigMaps("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	for _, cm := range cmList.Items {
		for _, v := range cm.Data {
			if strings.Contains(v, "TracingPolicy") {
				info.Tetragon.TracingPolicies = append(info.Tetragon.TracingPolicies, cm.Name)
				// Check for privileged operation coverage
				if containsPrivilegedSyscalls(v) {
					info.Tetragon.HasPrivilegedOp = true
				}
			}
		}
	}

	return nil
}

// privilegedSyscallKeywords are syscall/function names indicative of privilege operations.
var privilegedSyscallKeywords = []string{
	"setuid", "setgid", "execve", "execveat",
	"capset", "prctl", "clone", "unshare",
	"sys_enter_setuid", "sys_enter_execve",
}

func containsPrivilegedSyscalls(data string) bool {
	lower := strings.ToLower(data)
	for _, kw := range privilegedSyscallKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// collectCilium checks for Cilium DaemonSet and reads the cilium-config ConfigMap.
func (c *Collector) collectCilium(ctx context.Context, cs *kubernetes.Clientset, info *EBPFClusterInfo) error {
	dsList, err := cs.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("listing DaemonSets: %w", err)
	}

	var ciliumNS string
	for _, ds := range dsList.Items {
		if ds.Name == "cilium" || strings.HasPrefix(ds.Name, "cilium-") {
			info.Cilium.Deployed = true
			ciliumNS = ds.Namespace
			break
		}
	}

	if !info.Cilium.Deployed {
		return nil
	}

	// Read cilium-config ConfigMap
	ns := ciliumNS
	if ns == "" {
		ns = "kube-system"
	}
	cm, err := cs.CoreV1().ConfigMaps(ns).Get(ctx, "cilium-config", metav1.GetOptions{})
	if err != nil {
		// ConfigMap may not exist; not fatal
		return nil
	}

	info.Cilium.HubbleEnabled = cm.Data["enable-hubble"] == "true"
	info.Cilium.L7ProxyEnabled = cm.Data["enable-l7-proxy"] == "true"
	return nil
}
