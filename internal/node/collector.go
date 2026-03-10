package node

import (
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Collector fetches node information from a Kubernetes cluster.
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

	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}
	return cs, nil
}

// CollectAll fetches all nodes in the cluster.
func (c *Collector) CollectAll(ctx context.Context) ([]*NodeInfo, error) {
	cs, err := buildClientset(c.KubeconfigPath, c.Context)
	if err != nil {
		return nil, err
	}
	nodeList, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}
	return convertNodes(nodeList.Items), nil
}

// CollectOne fetches a single named node.
func (c *Collector) CollectOne(ctx context.Context, nodeName string) (*NodeInfo, error) {
	cs, err := buildClientset(c.KubeconfigPath, c.Context)
	if err != nil {
		return nil, err
	}
	n, err := cs.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting node %s: %w", nodeName, err)
	}
	return FromK8sNode(*n), nil
}

func convertNodes(nodes []corev1.Node) []*NodeInfo {
	result := make([]*NodeInfo, len(nodes))
	for i, n := range nodes {
		result[i] = FromK8sNode(n)
	}
	return result
}

// DefaultKubeconfig returns the default kubeconfig path.
func DefaultKubeconfig() string {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return kc
	}
	home, _ := os.UserHomeDir()
	return home + "/.kube/config"
}
