package cli

import (
	"fmt"
	"os"

	"github.com/NodeVet/nodevet/internal/audit"
	"github.com/NodeVet/nodevet/internal/checker"
	"github.com/NodeVet/nodevet/internal/render"
	"github.com/NodeVet/nodevet/internal/rules"
	"github.com/NodeVet/nodevet/internal/source"
	"github.com/spf13/cobra"
)

var (
	auditFlagAPIServerFlags string
	auditFlagAPIServerConfig string
	auditFlagPolicyFile      string
	auditFlagEmitPolicy      bool
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Validate audit log configuration and AuditPolicy completeness",
	Long: `Evaluate kube-apiserver audit logging flags and AuditPolicy YAML
for completeness against security best practices (CIS Kubernetes Benchmark 3.2.x).

Examples:
  nodevet audit --apiserver-flags "--audit-log-path=/var/log/audit.log --audit-log-maxage=30"
  nodevet audit --policy /etc/kubernetes/audit-policy.yaml
  nodevet audit --emit-policy > /etc/kubernetes/audit-policy.yaml

Exit codes:
  0  No findings
  1  One or more ERROR findings
  2  Only WARN findings`,
	RunE: runAudit,
}

func init() {
	auditCmd.Flags().StringVar(&auditFlagAPIServerFlags, "apiserver-flags", "", "Raw kube-apiserver startup flags string")
	auditCmd.Flags().StringVar(&auditFlagAPIServerConfig, "apiserver-config", "", "Path to kube-apiserver config YAML")
	auditCmd.Flags().StringVar(&auditFlagPolicyFile, "policy", "", "Path to AuditPolicy YAML file to evaluate")
	auditCmd.Flags().BoolVar(&auditFlagEmitPolicy, "emit-policy", false, "Print a recommended AuditPolicy YAML and exit")
}

func runAudit(cmd *cobra.Command, args []string) error {
	if auditFlagEmitPolicy {
		fmt.Print(audit.RecommendedPolicy)
		return nil
	}

	if auditFlagAPIServerFlags == "" && auditFlagAPIServerConfig == "" && auditFlagPolicyFile == "" {
		return fmt.Errorf("specify one or more of: --apiserver-flags, --apiserver-config, --policy, --emit-policy")
	}

	totalErrors := 0
	totalWarnings := 0

	// --- kube-apiserver audit log flag checks ---
	if auditFlagAPIServerFlags != "" || auditFlagAPIServerConfig != "" {
		var sources []source.ConfigSource
		if auditFlagAPIServerConfig != "" {
			sources = append(sources, source.NewYAMLSource(auditFlagAPIServerConfig))
		}
		if auditFlagAPIServerFlags != "" {
			sources = append(sources, source.NewFlagSource(auditFlagAPIServerFlags))
		}
		c := &checker.Checker{
			Sources: sources,
			Rules:   rules.AllAuditFlagRules(),
		}
		result, err := c.Run()
		if err != nil {
			return fmt.Errorf("audit flag check failed: %w", err)
		}
		fmt.Fprintln(os.Stderr, "=== kube-apiserver audit flags ===")
		renderer := render.New(os.Stdout)
		if err := renderer.Render(result); err != nil {
			return err
		}
		totalErrors += result.Errors
		totalWarnings += result.Warnings
	}

	// --- AuditPolicy completeness check ---
	if auditFlagPolicyFile != "" {
		policy, err := audit.LoadPolicy(auditFlagPolicyFile)
		if err != nil {
			return fmt.Errorf("loading audit policy: %w", err)
		}
		fmt.Fprintf(os.Stderr, "=== AuditPolicy: %s ===\n", auditFlagPolicyFile)
		c := &checker.AuditPolicyChecker{Rules: rules.AllAuditPolicyRules()}
		result := c.Run(policy)
		if OutputFormat == "json" {
			if err := render.WriteAuditJSON(os.Stdout, result); err != nil {
				return err
			}
		} else {
			renderer := render.NewAuditRenderer(os.Stdout)
			if err := renderer.RenderAudit(result); err != nil {
				return err
			}
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
