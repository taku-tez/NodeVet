package cli

import (
	"fmt"
	"os"

	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/render"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/source"
	"github.com/spf13/cobra"
)

var (
	flagConfigFile string
	flagFlagsStr   string
	flagNodeName   string
	flagKubeconfig string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Run kubelet security checks",
	Long: `Evaluate kubelet configuration against security best practices.

Sources (one or more can be combined; later sources override earlier):
  --config   KubeletConfiguration YAML file
  --flags    Raw kubelet startup flags string
  --node     Node name to fetch live config via /configz API

Exit codes:
  0  No findings
  1  One or more ERROR findings
  2  Only WARN findings (no ERRORs)`,
	RunE: runCheck,
}

func init() {
	checkCmd.Flags().StringVar(&flagConfigFile, "config", "", "Path to KubeletConfiguration YAML file")
	checkCmd.Flags().StringVar(&flagFlagsStr, "flags", "", "Raw kubelet startup flags (e.g. \"--anonymous-auth=false --tls-cert-file=/etc/k8s/kubelet.crt\")")
	checkCmd.Flags().StringVar(&flagNodeName, "node", "", "Node name for live /configz fetch")
	checkCmd.Flags().StringVar(&flagKubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to kubeconfig (for --node mode)")
}

func runCheck(cmd *cobra.Command, args []string) error {
	var sources []source.ConfigSource

	if flagConfigFile != "" {
		sources = append(sources, source.NewYAMLSource(flagConfigFile))
	}
	if flagFlagsStr != "" {
		sources = append(sources, source.NewFlagSource(flagFlagsStr))
	}
	if flagNodeName != "" {
		kc := flagKubeconfig
		if kc == "" {
			home, _ := os.UserHomeDir()
			kc = home + "/.kube/config"
		}
		sources = append(sources, source.NewConfigzSource(flagNodeName, kc))
	}

	if len(sources) == 0 {
		return fmt.Errorf("no input source specified; use --config, --flags, or --node")
	}

	c := &checker.Checker{
		Sources: sources,
		Rules:   rules.All(),
	}

	result, err := c.Run()
	if err != nil {
		return fmt.Errorf("check failed: %w", err)
	}

	if OutputFormat == "json" {
		if err := render.WriteCheckerJSON(os.Stdout, result); err != nil {
			return err
		}
	} else {
		renderer := render.New(os.Stdout)
		if err := renderer.Render(result); err != nil {
			return err
		}
	}

	// Exit codes: 0=clean, 1=errors, 2=warnings only
	if result.Errors > 0 {
		os.Exit(1)
	}
	if result.Warnings > 0 {
		os.Exit(2)
	}
	return nil
}
