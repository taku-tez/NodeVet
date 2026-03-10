package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/node"
	"github.com/NodeVet/nodevet/internal/render"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/runtime"
	intsource "github.com/NodeVet/nodevet/internal/source"
	"github.com/spf13/cobra"
)

var (
	runtimeFlagContainerdConfig string
	runtimeFlagRuntimeClass     bool
	runtimeFlagKubeconfig       string
	runtimeFlagContext          string
)

var runtimeCmd = &cobra.Command{
	Use:   "runtime",
	Short: "Scan container runtime configuration",
	Long: `Evaluate containerd configuration and cluster RuntimeClass objects
against security best practices.

Examples:
  nodevet runtime --config /etc/containerd/config.toml
  nodevet runtime --runtimeclass
  nodevet runtime --config /etc/containerd/config.toml --runtimeclass

Exit codes:
  0  No findings
  1  One or more ERROR findings
  2  Only WARN findings`,
	RunE: runRuntime,
}

func init() {
	runtimeCmd.Flags().StringVar(&runtimeFlagContainerdConfig, "config", "", "Path to containerd config.toml")
	runtimeCmd.Flags().BoolVar(&runtimeFlagRuntimeClass, "runtimeclass", false, "Check RuntimeClass objects in the cluster")
	runtimeCmd.Flags().StringVar(&runtimeFlagKubeconfig, "kubeconfig", node.DefaultKubeconfig(), "Path to kubeconfig (for --runtimeclass)")
	runtimeCmd.Flags().StringVar(&runtimeFlagContext, "context", "", "Kubernetes context (for --runtimeclass)")
}

func runRuntime(cmd *cobra.Command, args []string) error {
	if runtimeFlagContainerdConfig == "" && !runtimeFlagRuntimeClass {
		return fmt.Errorf("specify --config <containerd-config.toml> and/or --runtimeclass")
	}

	totalErrors := 0
	totalWarnings := 0

	// --- containerd config check ---
	if runtimeFlagContainerdConfig != "" {
		src := intsource.NewContainerdSource(runtimeFlagContainerdConfig)
		c := &checker.Checker{
			Sources: []intsource.ConfigSource{src},
			Rules:   rules.AllRuntimeRules(),
		}
		result, err := c.Run()
		if err != nil {
			return fmt.Errorf("containerd check failed: %w", err)
		}
		fmt.Fprintln(os.Stderr, "=== containerd config ===")
		renderer := render.New(os.Stdout)
		if err := renderer.Render(result); err != nil {
			return err
		}
		totalErrors += result.Errors
		totalWarnings += result.Warnings
	}

	// --- RuntimeClass check ---
	if runtimeFlagRuntimeClass {
		col := &runtime.Collector{
			KubeconfigPath: runtimeFlagKubeconfig,
			Context:        runtimeFlagContext,
		}
		info, err := col.CollectRuntimeClasses(context.Background())
		if err != nil {
			return fmt.Errorf("collecting RuntimeClasses: %w", err)
		}
		fmt.Fprintf(os.Stderr, "=== RuntimeClass (%d found) ===\n", len(info.RuntimeClasses))
		c := &checker.RuntimeClassChecker{Rules: rules.AllRuntimeClassRules()}
		result := c.Run(info)
		renderer := render.NewRuntimeClassRenderer(os.Stdout)
		if err := renderer.RenderRuntimeClass(result); err != nil {
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
