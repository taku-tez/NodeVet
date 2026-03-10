package rules

import "github.com/NodeVet/nodevet/internal/ebpf"

// EBPFRule checks the eBPF/runtime security tool configuration of a cluster.
type EBPFRule struct {
	ID          string
	Title       string
	Severity    Severity
	Description string
	Remediation string
	Check       func(info *ebpf.EBPFClusterInfo) *EBPFFinding
}

// EBPFFinding is produced by an EBPFRule.
type EBPFFinding struct {
	Rule    *EBPFRule
	Actual  string
	Message string
}

// EBPFResult holds all eBPF/runtime security findings.
type EBPFResult struct {
	Findings []*EBPFFinding
	Passed   int
	Errors   int
	Warnings int
}
