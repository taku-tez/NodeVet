package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/ebpf"
	"github.com/NodeVet/nodevet/internal/node"
	"github.com/NodeVet/nodevet/internal/render"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/spf13/cobra"
)

var (
	ebpfFlagKubeconfig string
	ebpfFlagContext    string
)

var ebpfCmd = &cobra.Command{
	Use:   "ebpf",
	Short: "Scan eBPF and runtime security tool configuration",
	Long: `Evaluate the deployment and configuration of Falco, Tetragon, and Cilium
for runtime security coverage gaps.

Examples:
  nodevet ebpf
  nodevet ebpf --context my-cluster
  nodevet ebpf --kubeconfig /path/to/kubeconfig

Exit codes:
  0  No findings
  1  One or more ERROR findings
  2  Only WARN findings`,
	RunE: runEBPF,
}

func init() {
	ebpfCmd.Flags().StringVar(&ebpfFlagKubeconfig, "kubeconfig", node.DefaultKubeconfig(), "Path to kubeconfig")
	ebpfCmd.Flags().StringVar(&ebpfFlagContext, "context", "", "Kubernetes context name")
}

func runEBPF(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	col := &ebpf.Collector{
		KubeconfigPath: ebpfFlagKubeconfig,
		Context:        ebpfFlagContext,
	}

	info, err := col.Collect(ctx)
	if err != nil {
		return fmt.Errorf("collecting eBPF cluster state: %w", err)
	}

	logEBPFSummary(info)

	c := &checker.EBPFChecker{Rules: rules.AllEBPFRules()}
	result := c.Run(info)

	renderer := render.NewEBPFRenderer(os.Stdout)
	if err := renderer.RenderEBPF(result); err != nil {
		return err
	}

	if result.Errors > 0 {
		os.Exit(1)
	}
	if result.Warnings > 0 {
		os.Exit(2)
	}
	return nil
}

func logEBPFSummary(info *ebpf.EBPFClusterInfo) {
	fmt.Fprintf(os.Stderr, "=== eBPF/Runtime Security ===\n")
	fmt.Fprintf(os.Stderr, "  Falco: deployed=%v, webhook=%v, ruleFiles=%d\n",
		info.Falco.Deployed, info.Falco.OutputWebhook, len(info.Falco.RulesFiles))
	fmt.Fprintf(os.Stderr, "  Tetragon: deployed=%v, policies=%d, privOps=%v\n",
		info.Tetragon.Deployed, len(info.Tetragon.TracingPolicies), info.Tetragon.HasPrivilegedOp)
	fmt.Fprintf(os.Stderr, "  Cilium: deployed=%v, hubble=%v, l7proxy=%v\n",
		info.Cilium.Deployed, info.Cilium.HubbleEnabled, info.Cilium.L7ProxyEnabled)
}
