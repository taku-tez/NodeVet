package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/node"
	"github.com/NodeVet/nodevet/internal/render"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/spf13/cobra"
)

var (
	clusterFlagContext    string
	clusterFlagKubeconfig string
	clusterFlagNode       string
	clusterFlagAllNodes   bool
)

var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Scan live cluster nodes for security issues",
	Long: `Fetch node configuration from a live Kubernetes cluster and evaluate
node-level security rules (node conditions, GKE/EKS/AKS-specific checks).

Examples:
  nodevet cluster --all-nodes
  nodevet cluster --node gke-my-cluster-pool-abc123
  nodevet cluster --context my-context --kubeconfig ~/.kube/config

Exit codes:
  0  No findings
  1  One or more ERROR findings
  2  Only WARN findings`,
	RunE: runCluster,
}

func init() {
	clusterCmd.Flags().StringVar(&clusterFlagContext, "context", "", "Kubernetes context name")
	clusterCmd.Flags().StringVar(&clusterFlagKubeconfig, "kubeconfig", node.DefaultKubeconfig(), "Path to kubeconfig")
	clusterCmd.Flags().StringVar(&clusterFlagNode, "node", "", "Scan a specific node by name")
	clusterCmd.Flags().BoolVar(&clusterFlagAllNodes, "all-nodes", false, "Scan all nodes in the cluster")
}

func runCluster(cmd *cobra.Command, args []string) error {
	if clusterFlagNode == "" && !clusterFlagAllNodes {
		return fmt.Errorf("specify --node <name> or --all-nodes")
	}

	collector := &node.Collector{
		KubeconfigPath: clusterFlagKubeconfig,
		Context:        clusterFlagContext,
	}

	ctx := context.Background()
	var nodes []*node.NodeInfo

	if clusterFlagAllNodes {
		var err error
		nodes, err = collector.CollectAll(ctx)
		if err != nil {
			return fmt.Errorf("collecting nodes: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Scanning %d node(s)...\n", len(nodes))
	} else {
		n, err := collector.CollectOne(ctx, clusterFlagNode)
		if err != nil {
			return fmt.Errorf("collecting node: %w", err)
		}
		nodes = []*node.NodeInfo{n}
		fmt.Fprintf(os.Stderr, "Scanning node: %s (platform: %s)\n", n.Name, n.Platform)
	}

	c := &checker.NodeChecker{Rules: rules.AllNodeRules()}
	result := c.RunNodes(nodes)

	if OutputFormat == "json" {
		if err := render.WriteNodeJSON(os.Stdout, result); err != nil {
			return err
		}
	} else {
		renderer := render.NewNodeRenderer(os.Stdout)
		if err := renderer.RenderNodes(result); err != nil {
			return err
		}
	}

	if result.Errors > 0 {
		os.Exit(1)
	}
	if result.Warnings > 0 {
		os.Exit(2)
	}
	return nil
}
