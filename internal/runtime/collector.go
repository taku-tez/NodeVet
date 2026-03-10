package runtime

import (
	"context"
	"fmt"

	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Collector fetches RuntimeClass information from a Kubernetes cluster.
type Collector struct {
	KubeconfigPath string
	Context        string
}

func buildClientset(kubeconfigPath, kubeContext string) (*kubernetes.Clientset, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	if kubeContext != "" {
		overrides.CurrentContext = kubeContext
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// CollectRuntimeClasses fetches all RuntimeClass objects from the cluster.
func (c *Collector) CollectRuntimeClasses(ctx context.Context) (*ClusterRuntimeInfo, error) {
	cs, err := buildClientset(c.KubeconfigPath, c.Context)
	if err != nil {
		return nil, err
	}
	list, err := cs.NodeV1().RuntimeClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing RuntimeClasses: %w", err)
	}
	return &ClusterRuntimeInfo{
		RuntimeClasses: convertRuntimeClasses(list.Items),
	}, nil
}

func convertRuntimeClasses(items []nodev1.RuntimeClass) []RuntimeClassInfo {
	result := make([]RuntimeClassInfo, len(items))
	for i, rc := range items {
		result[i] = RuntimeClassInfo{
			Name:    rc.Name,
			Handler: rc.Handler,
		}
	}
	return result
}
