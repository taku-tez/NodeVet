package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/NodeVet/nodevet/internal/access"
	"github.com/NodeVet/nodevet/internal/audit"
	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/correlate"
	"github.com/NodeVet/nodevet/internal/node"
	"github.com/NodeVet/nodevet/internal/render"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/source"
	"github.com/spf13/cobra"
)

var (
	scanFlagConfig         string
	scanFlagFlagsStr       string
	scanFlagNodeName       string
	scanFlagAPIServerFlags string
	scanFlagRBAC           bool
	scanFlagPods           bool
	scanFlagPolicyFile     string
	scanFlagKubeconfig     string
	scanFlagContext        string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run all checks and detect compound attack paths",
	Long: `Run kubelet, kube-apiserver, RBAC, pod, and audit policy checks together,
then correlate findings to surface compound attack paths that individual checks miss.

Examples:
  nodevet scan --config /etc/kubernetes/kubelet.yaml \
               --apiserver-flags "--authorization-mode=Node,RBAC" \
               --rbac --pods \
               --policy /etc/kubernetes/audit-policy.yaml

Exit codes:
  0  No findings
  1  One or more ERROR or CRITICAL correlation findings
  2  Only WARN findings`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanFlagConfig, "config", "", "Path to KubeletConfiguration YAML file")
	scanCmd.Flags().StringVar(&scanFlagFlagsStr, "flags", "", "Raw kubelet startup flags string")
	scanCmd.Flags().StringVar(&scanFlagNodeName, "node", "", "Node name for live /configz fetch")
	scanCmd.Flags().StringVar(&scanFlagAPIServerFlags, "apiserver-flags", "", "Raw kube-apiserver startup flags string")
	scanCmd.Flags().BoolVar(&scanFlagRBAC, "rbac", false, "Scan cluster RBAC for dangerous bindings")
	scanCmd.Flags().BoolVar(&scanFlagPods, "pods", false, "Scan running pods for privileged/hostPID risks")
	scanCmd.Flags().StringVar(&scanFlagPolicyFile, "policy", "", "Path to AuditPolicy YAML file")
	scanCmd.Flags().StringVar(&scanFlagKubeconfig, "kubeconfig", node.DefaultKubeconfig(), "Path to kubeconfig")
	scanCmd.Flags().StringVar(&scanFlagContext, "context", "", "Kubernetes context name")
}

func runScan(cmd *cobra.Command, args []string) error {
	if scanFlagConfig == "" && scanFlagFlagsStr == "" && scanFlagNodeName == "" &&
		scanFlagAPIServerFlags == "" && !scanFlagRBAC && !scanFlagPods && scanFlagPolicyFile == "" {
		return fmt.Errorf("specify at least one input: --config, --flags, --node, --apiserver-flags, --rbac, --pods, --policy")
	}

	var firedIDs []string
	totalErrors, totalWarnings := 0, 0

	// --- kubelet config check ---
	if scanFlagConfig != "" || scanFlagFlagsStr != "" || scanFlagNodeName != "" {
		var srcs []source.ConfigSource
		if scanFlagConfig != "" {
			srcs = append(srcs, source.NewYAMLSource(scanFlagConfig))
		}
		if scanFlagFlagsStr != "" {
			srcs = append(srcs, source.NewFlagSource(scanFlagFlagsStr))
		}
		if scanFlagNodeName != "" {
			kc := scanFlagKubeconfig
			if kc == "" {
				home, _ := os.UserHomeDir()
				kc = home + "/.kube/config"
			}
			srcs = append(srcs, source.NewConfigzSource(scanFlagNodeName, kc))
		}
		c := &checker.Checker{Sources: srcs, Rules: rules.All()}
		result, err := c.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "kubelet check error: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "=== kubelet config ===")
			renderer := render.New(os.Stdout)
			if err := renderer.Render(result); err != nil {
				return err
			}
			for _, f := range result.Findings {
				firedIDs = append(firedIDs, f.Rule.ID)
			}
			totalErrors += result.Errors
			totalWarnings += result.Warnings
		}
	}

	// --- kube-apiserver access config check ---
	if scanFlagAPIServerFlags != "" {
		c := &checker.Checker{
			Sources: []source.ConfigSource{source.NewFlagSource(scanFlagAPIServerFlags)},
			Rules:   rules.AllAPIServerRules(),
		}
		result, err := c.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "apiserver check error: %v\n", err)
		} else {
			fmt.Fprintln(os.Stderr, "=== kube-apiserver ===")
			renderer := render.New(os.Stdout)
			if err := renderer.Render(result); err != nil {
				return err
			}
			for _, f := range result.Findings {
				firedIDs = append(firedIDs, f.Rule.ID)
			}
			totalErrors += result.Errors
			totalWarnings += result.Warnings
		}
	}

	// --- RBAC + Pod scan ---
	if scanFlagRBAC || scanFlagPods {
		col := &access.RBACCollector{
			KubeconfigPath: scanFlagKubeconfig,
			Context:        scanFlagContext,
		}
		ctx := context.Background()
		info := &access.ClusterAccessInfo{}

		if scanFlagRBAC {
			nodeProxy, podExec, err := col.CollectRBACRisks(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "RBAC collection error: %v\n", err)
			} else {
				info.NodeProxyBindings = nodeProxy
				info.PodExecBindings = podExec
			}
		}
		if scanFlagPods {
			pods, err := col.CollectPodRisks(ctx)
			if err != nil {
				fmt.Fprintf(os.Stderr, "pod collection error: %v\n", err)
			} else {
				info.RiskyPods = pods
			}
		}

		fmt.Fprintln(os.Stderr, "=== access control ===")
		c := &checker.AccessChecker{Rules: rules.AllAccessRules()}
		result := c.Run(info)
		renderer := render.NewAccessRenderer(os.Stdout)
		if err := renderer.RenderAccess(result); err != nil {
			return err
		}
		for _, f := range result.Findings {
			firedIDs = append(firedIDs, f.Rule.ID)
		}
		totalErrors += result.Errors
		totalWarnings += result.Warnings
	}

	// --- AuditPolicy completeness check ---
	if scanFlagPolicyFile != "" {
		policy, err := audit.LoadPolicy(scanFlagPolicyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "audit policy load error: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "=== AuditPolicy: %s ===\n", scanFlagPolicyFile)
			c := &checker.AuditPolicyChecker{Rules: rules.AllAuditPolicyRules()}
			result := c.Run(policy)
			renderer := render.NewAuditRenderer(os.Stdout)
			if err := renderer.RenderAudit(result); err != nil {
				return err
			}
			for _, f := range result.Findings {
				firedIDs = append(firedIDs, f.Rule.ID)
			}
			totalErrors += result.Errors
			totalWarnings += result.Warnings
		}
	}

	// --- Correlation ---
	correlations := correlate.Correlate(firedIDs)
	if err := render.RenderCorrelations(os.Stdout, correlations); err != nil {
		return err
	}
	for _, c := range correlations {
		if rules.SeverityIsHighOrAbove(c.Severity) {
			totalErrors++
		} else {
			totalWarnings++
		}
	}

	if totalErrors > 0 {
		os.Exit(1)
	}
	if totalWarnings > 0 {
		os.Exit(2)
	}
	return nil
}
