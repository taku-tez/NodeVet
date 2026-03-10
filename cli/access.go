package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/NodeVet/nodevet/internal/access"
	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/node"
	"github.com/NodeVet/nodevet/internal/render"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/source"
	"github.com/spf13/cobra"
)

var (
	accessFlagAPIServerFlags string
	accessFlagAPIServerConfig string
	accessFlagRBAC            bool
	accessFlagPods            bool
	accessFlagKubeconfig      string
	accessFlagContext         string
)

var accessCmd = &cobra.Command{
	Use:   "access",
	Short: "Scan node access control configuration",
	Long: `Evaluate kube-apiserver authorization settings, RBAC bindings,
and running pod configurations for node access risks.

Examples:
  nodevet access --apiserver-flags "--authorization-mode=Node,RBAC --enable-admission-plugins=NodeRestriction"
  nodevet access --rbac
  nodevet access --pods
  nodevet access --rbac --pods

Exit codes:
  0  No findings
  1  One or more ERROR findings
  2  Only WARN findings`,
	RunE: runAccess,
}

func init() {
	accessCmd.Flags().StringVar(&accessFlagAPIServerFlags, "apiserver-flags", "", "Raw kube-apiserver startup flags string")
	accessCmd.Flags().StringVar(&accessFlagAPIServerConfig, "apiserver-config", "", "Path to kube-apiserver config YAML")
	accessCmd.Flags().BoolVar(&accessFlagRBAC, "rbac", false, "Scan cluster RBAC for dangerous node/pod access bindings")
	accessCmd.Flags().BoolVar(&accessFlagPods, "pods", false, "Scan running pods for privileged/hostPID/hostPath risks")
	accessCmd.Flags().StringVar(&accessFlagKubeconfig, "kubeconfig", node.DefaultKubeconfig(), "Path to kubeconfig")
	accessCmd.Flags().StringVar(&accessFlagContext, "context", "", "Kubernetes context name")
}

func runAccess(cmd *cobra.Command, args []string) error {
	if accessFlagAPIServerFlags == "" && accessFlagAPIServerConfig == "" && !accessFlagRBAC && !accessFlagPods {
		return fmt.Errorf("specify one or more of: --apiserver-flags, --apiserver-config, --rbac, --pods")
	}

	totalErrors := 0
	totalWarnings := 0

	// --- kube-apiserver config check ---
	if accessFlagAPIServerFlags != "" || accessFlagAPIServerConfig != "" {
		var sources []source.ConfigSource
		if accessFlagAPIServerConfig != "" {
			sources = append(sources, source.NewYAMLSource(accessFlagAPIServerConfig))
		}
		if accessFlagAPIServerFlags != "" {
			sources = append(sources, source.NewFlagSource(accessFlagAPIServerFlags))
		}

		c := &checker.Checker{
			Sources: sources,
			Rules:   rules.AllAPIServerRules(),
		}
		result, err := c.Run()
		if err != nil {
			return fmt.Errorf("apiserver check failed: %w", err)
		}
		fmt.Fprintln(os.Stderr, "=== kube-apiserver ===")
		renderer := render.New(os.Stdout)
		if err := renderer.Render(result); err != nil {
			return err
		}
		totalErrors += result.Errors
		totalWarnings += result.Warnings
	}

	// --- RBAC + Pod scan ---
	if accessFlagRBAC || accessFlagPods {
		col := &access.RBACCollector{
			KubeconfigPath: accessFlagKubeconfig,
			Context:        accessFlagContext,
		}
		ctx := context.Background()
		info := &access.ClusterAccessInfo{}

		if accessFlagRBAC {
			nodeProxy, podExec, err := col.CollectRBACRisks(ctx)
			if err != nil {
				return fmt.Errorf("collecting RBAC: %w", err)
			}
			info.NodeProxyBindings = nodeProxy
			info.PodExecBindings = podExec
			fmt.Fprintf(os.Stderr, "=== RBAC (nodes/proxy bindings: %d, pods/exec bindings: %d) ===\n",
				len(nodeProxy), len(podExec))
		}

		if accessFlagPods {
			pods, err := col.CollectPodRisks(ctx)
			if err != nil {
				return fmt.Errorf("collecting pod risks: %w", err)
			}
			info.RiskyPods = pods
			fmt.Fprintf(os.Stderr, "=== Pods (risky pods: %d) ===\n", len(pods))
		}

		c := &checker.AccessChecker{Rules: rules.AllAccessRules()}
		result := c.Run(info)
		renderer := render.NewAccessRenderer(os.Stdout)
		if err := renderer.RenderAccess(result); err != nil {
			return err
		}
		totalErrors += result.Errors
		totalWarnings += result.Warnings
	}

	if totalErrors > 0 {
		os.Exit(1)
	}
	if totalWarnings > 0 {
		os.Exit(2)
	}
	return nil
}
