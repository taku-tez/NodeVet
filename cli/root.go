package cli

import "github.com/spf13/cobra"

// OutputFormat is the global output format flag (tty or json).
var OutputFormat string

var rootCmd = &cobra.Command{
	Use:   "nodevet",
	Short: "Kubernetes kubelet & node security validation tool",
	Long: `NodeVet validates kubelet configuration, container runtime, and node access
controls against security best practices (CIS Kubernetes Benchmark).`,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&OutputFormat, "format", "tty", "Output format: tty, json")
	rootCmd.AddCommand(checkCmd)
	rootCmd.AddCommand(clusterCmd)
	rootCmd.AddCommand(runtimeCmd)
	rootCmd.AddCommand(accessCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(ebpfCmd)
	rootCmd.AddCommand(scanCmd)
}
