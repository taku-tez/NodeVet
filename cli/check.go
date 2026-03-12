package cli

import (
	"fmt"
	"os"
	"strings"

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
	var staticSources []source.ConfigSource
	var liveSource source.ConfigSource

	if flagConfigFile != "" {
		staticSources = append(staticSources, source.NewYAMLSource(flagConfigFile))
	}
	if flagFlagsStr != "" {
		staticSources = append(staticSources, source.NewFlagSource(flagFlagsStr))
	}
	if flagNodeName != "" {
		kc := flagKubeconfig
		if kc == "" {
			home, _ := os.UserHomeDir()
			kc = home + "/.kube/config"
		}
		liveSource = source.NewConfigzSource(flagNodeName, kc)
	}

	allSources := append(staticSources, func() []source.ConfigSource {
		if liveSource != nil {
			return []source.ConfigSource{liveSource}
		}
		return nil
	}()...)

	if len(allSources) == 0 {
		return fmt.Errorf("no input source specified; use --config, --flags, or --node")
	}

	c := &checker.Checker{
		Sources: allSources,
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

	// Configz vs static discrepancy check: only when both static and live sources are present.
	if len(staticSources) > 0 && liveSource != nil {
		if discrepancies, dErr := runDiscrepancyCheck(staticSources, liveSource); dErr != nil {
			fmt.Fprintf(os.Stderr, "warning: discrepancy check failed: %v\n", dErr)
		} else if len(discrepancies) > 0 {
			fmt.Fprintln(os.Stderr, "\n=== Config Drift Detected (static vs live) ===")
			fmt.Fprintf(os.Stderr, "%-30s  %-20s  %-20s\n", "KEY", "STATIC (desired)", "LIVE (running)")
			fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("-", 75))
			for _, d := range discrepancies {
				fmt.Fprintf(os.Stderr, "%-30s  %-20s  %-20s  [CRITICAL: config drift]\n",
					d.Key, d.StaticValue, d.LiveValue)
			}
			// Count as errors
			result.Errors += len(discrepancies)
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

// runDiscrepancyCheck loads static sources and live source, then compares them.
func runDiscrepancyCheck(staticSources []source.ConfigSource, live source.ConfigSource) ([]source.Discrepancy, error) {
	var staticMaps []map[string]string
	for _, s := range staticSources {
		m, err := s.Load()
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", s.SourceName(), err)
		}
		staticMaps = append(staticMaps, m)
	}
	liveMap, err := live.Load()
	if err != nil {
		return nil, fmt.Errorf("loading %s: %w", live.SourceName(), err)
	}
	return source.FindDiscrepancies(source.Merge(staticMaps...), liveMap), nil
}
