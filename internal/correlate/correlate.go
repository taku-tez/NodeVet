package correlate

import "github.com/NodeVet/nodevet/internal/rules"

// Finding describes a compound risk produced when multiple rules fire together.
type Finding struct {
	ID          string
	Title       string
	Severity    rules.Severity
	RuleIDs     []string // contributing rule IDs
	Message     string
	Remediation string
}

// rule defines the conditions for a compound finding.
type rule struct {
	ID          string
	Title       string
	Severity    rules.Severity
	RequiredIDs []string // all must be present in the fired set
	Message     string
	Remediation string
}

// allRules lists every compound correlation check (C001–C005).
var allRules = []rule{
	{
		ID:          "C001",
		Title:       "Unaudited exec path: pods/exec permitted but not logged",
		Severity:    rules.SeverityCritical,
		RequiredIDs: []string{"NV3302", "NV5102"},
		Message: "pods/exec access is broadly granted (NV3302) AND pod exec/attach is not captured " +
			"in audit logs (NV5102). An attacker can execute commands in any pod with zero audit trail.",
		Remediation: "Add pods/exec audit rule to AuditPolicy (fix NV5102), then restrict exec bindings (NV3302).",
	},
	{
		ID:          "C002",
		Title:       "Unauthenticated access combined with broad exec permissions",
		Severity:    rules.SeverityCritical,
		RequiredIDs: []string{"NV1001", "NV3302"},
		Message: "kubelet anonymous-auth is enabled (NV1001) AND pods/exec is broadly granted (NV3302). " +
			"Anonymous users can probe kubelet while other identities exec into pods undetected.",
		Remediation: "Disable anonymous-auth immediately (NV1001). Restrict pods/exec bindings (NV3302).",
	},
	{
		ID:          "C003",
		Title:       "Node escape chain with no audit trail",
		Severity:    rules.SeverityCritical,
		RequiredIDs: []string{"NV3305", "NV5102"},
		Message: "A pod with node escape capabilities exists (NV3305: hostPID+privileged) AND pod exec " +
			"is not audited (NV5102). A successful node compromise would leave no trace in audit logs.",
		Remediation: "Remove hostPID+privileged from pod spec (NV3305). Add pods/exec audit rule (NV5102).",
	},
	{
		ID:          "C004",
		Title:       "AlwaysAllow authorization with open node proxy access",
		Severity:    rules.SeverityCritical,
		RequiredIDs: []string{"NV1002", "NV3301"},
		Message: "kubelet authorization-mode is AlwaysAllow (NV1002) AND nodes/proxy is broadly granted " +
			"(NV3301). All requests to the kubelet API are accepted without restriction.",
		Remediation: "Set authorization-mode=Webhook (NV1002). Remove unnecessary nodes/proxy bindings (NV3301).",
	},
	{
		ID:          "C005",
		Title:       "Privileged pod running while exec actions are not audited",
		Severity:    rules.SeverityHigh,
		RequiredIDs: []string{"NV3304", "NV5102"},
		Message: "Privileged containers are running (NV3304) AND pod exec/attach is not logged (NV5102). " +
			"An attacker who execs into a privileged container could escape to the node with no audit evidence.",
		Remediation: "Remove privileged:true from containers (NV3304). Add pods/exec audit rule (NV5102).",
	},
}

// Correlate returns compound findings for the given set of fired rule IDs.
func Correlate(firedIDs []string) []Finding {
	fired := make(map[string]bool, len(firedIDs))
	for _, id := range firedIDs {
		fired[id] = true
	}

	var findings []Finding
	for _, r := range allRules {
		if allPresent(fired, r.RequiredIDs) {
			findings = append(findings, Finding{
				ID:          r.ID,
				Title:       r.Title,
				Severity:    r.Severity,
				RuleIDs:     r.RequiredIDs,
				Message:     r.Message,
				Remediation: r.Remediation,
			})
		}
	}
	return findings
}

func allPresent(fired map[string]bool, ids []string) bool {
	for _, id := range ids {
		if !fired[id] {
			return false
		}
	}
	return true
}
