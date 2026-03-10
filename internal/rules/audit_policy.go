package rules

import (
	"fmt"

	"github.com/NodeVet/nodevet/internal/audit"
)

// AuditPolicyRule checks a parsed AuditPolicy for completeness.
type AuditPolicyRule struct {
	ID          string
	Title       string
	Severity    Severity
	Description string
	Remediation string
	Check       func(policy *audit.Policy) *AuditPolicyFinding
}

// AuditPolicyFinding is produced when an AuditPolicyRule detects a gap.
type AuditPolicyFinding struct {
	Rule    *AuditPolicyRule
	Actual  string
	Message string
	Gap     string // description of what is not being logged
}

// AuditPolicyResult holds all AuditPolicy findings.
type AuditPolicyResult struct {
	Findings []*AuditPolicyFinding
	Passed   int
	Errors   int
	Warnings int
}

// NV5101: Secrets must be logged at RequestResponse level
var ruleAuditSecrets = AuditPolicyRule{
	ID:          "NV5101",
	Title:       "AuditPolicy: Secrets access must be logged at RequestResponse level",
	Severity:    SeverityError,
	Description: "The AuditPolicy does not log Secret reads/writes at RequestResponse level. Credential access will not be captured in audit logs.",
	Remediation: "Add a rule before any catch-all: level: RequestResponse, resources: [{group: \"\", resources: [\"secrets\"]}]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		ops := []audit.AuditOperation{
			{Verb: "get", Group: "", Resource: "secrets"},
			{Verb: "list", Group: "", Resource: "secrets"},
		}
		for _, op := range ops {
			level := policy.FindLevel(op)
			if !level.AtLeast(audit.LevelRequest) {
				return &AuditPolicyFinding{
					Actual:  string(level),
					Gap:     fmt.Sprintf("secrets/%s", op.Verb),
					Message: fmt.Sprintf("secrets %s is audited at '%s'; expected at least 'Request'", op.Verb, level),
				}
			}
		}
		return nil
	},
}

// NV5102: Pod exec/attach must be logged
var ruleAuditPodExec = AuditPolicyRule{
	ID:          "NV5102",
	Title:       "AuditPolicy: pods/exec and pods/attach must be logged",
	Severity:    SeverityError,
	Description: "The AuditPolicy does not log pod exec/attach requests. Interactive sessions inside containers will not appear in audit logs.",
	Remediation: "Add a rule: level: Request, resources: [{group: \"\", resources: [\"pods/exec\", \"pods/attach\"]}], verbs: [\"create\", \"get\"]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		execOp := audit.AuditOperation{Verb: "create", Group: "", Resource: "pods/exec"}
		level := policy.FindLevel(execOp)
		if !level.AtLeast(audit.LevelMetadata) {
			return &AuditPolicyFinding{
				Actual:  string(level),
				Gap:     "pods/exec",
				Message: fmt.Sprintf("pods/exec is audited at '%s'; exec sessions are invisible in audit logs", level),
			}
		}
		return nil
	},
}

// NV5103: system:anonymous actions must be logged
var ruleAuditAnonymous = AuditPolicyRule{
	ID:          "NV5103",
	Title:       "AuditPolicy: system:anonymous actions must be logged",
	Severity:    SeverityError,
	Description: "The AuditPolicy does not log actions by system:anonymous. Unauthenticated probing of the API server will not appear in audit logs.",
	Remediation: "Add a rule: level: RequestResponse, userGroups: [\"system:anonymous\"]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		op := audit.AuditOperation{UserGroup: "system:anonymous", Verb: "get", Resource: "pods"}
		level := policy.FindLevel(op)
		if !level.AtLeast(audit.LevelMetadata) {
			return &AuditPolicyFinding{
				Actual:  string(level),
				Gap:     "system:anonymous",
				Message: fmt.Sprintf("system:anonymous actions are at level '%s'; unauthenticated API access is invisible", level),
			}
		}
		return nil
	},
}

// NV5104: policy must not default to None for all requests
var ruleAuditCatchAll = AuditPolicyRule{
	ID:          "NV5104",
	Title:       "AuditPolicy: catch-all rule must not be level:None",
	Severity:    SeverityError,
	Description: "The AuditPolicy catch-all rule (empty matcher) is set to level:None. Most API operations will not be logged.",
	Remediation: "Change the catch-all rule to level: Metadata to ensure at least basic audit metadata is captured for all requests.",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		// Check what level a generic operation hits
		op := audit.AuditOperation{Verb: "list", Group: "apps", Resource: "deployments"}
		level := policy.FindLevel(op)
		if level == audit.LevelNone {
			return &AuditPolicyFinding{
				Actual:  "None",
				Gap:     "default catch-all",
				Message: "catch-all rule is None; most API operations are not being audited",
			}
		}
		return nil
	},
}

// NV5105: RBAC mutations must be logged at RequestResponse
var ruleAuditRBACMutations = AuditPolicyRule{
	ID:          "NV5105",
	Title:       "AuditPolicy: RBAC mutations should be logged at RequestResponse level",
	Severity:    SeverityWarn,
	Description: "The AuditPolicy does not log RBAC ClusterRole/RoleBinding changes at RequestResponse level. Privilege escalation attempts may not be fully captured.",
	Remediation: "Add a rule: level: RequestResponse, resources: [{group: \"rbac.authorization.k8s.io\", resources: [\"clusterroles\", \"clusterrolebindings\"]}], verbs: [\"create\", \"update\", \"patch\", \"delete\"]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		op := audit.AuditOperation{
			Verb:     "create",
			Group:    "rbac.authorization.k8s.io",
			Resource: "clusterrolebindings",
		}
		level := policy.FindLevel(op)
		if !level.AtLeast(audit.LevelRequest) {
			return &AuditPolicyFinding{
				Actual:  string(level),
				Gap:     "rbac.authorization.k8s.io/clusterrolebindings create",
				Message: fmt.Sprintf("RBAC binding mutations logged at '%s'; privilege escalation details may be missing", level),
			}
		}
		return nil
	},
}

// NV5106: Webhook configuration changes must be logged
var ruleAuditWebhookMutations = AuditPolicyRule{
	ID:          "NV5106",
	Title:       "AuditPolicy: webhook configuration changes should be logged",
	Severity:    SeverityWarn,
	Description: "The AuditPolicy does not log changes to MutatingWebhookConfiguration at Request level or above. Admission webhook tampering may go undetected.",
	Remediation: "Add a rule: level: RequestResponse, resources: [{group: \"admissionregistration.k8s.io\", resources: [\"mutatingwebhookconfigurations\"]}], verbs: [\"create\", \"update\", \"patch\", \"delete\"]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		op := audit.AuditOperation{
			Verb:     "create",
			Group:    "admissionregistration.k8s.io",
			Resource: "mutatingwebhookconfigurations",
		}
		level := policy.FindLevel(op)
		if !level.AtLeast(audit.LevelMetadata) {
			return &AuditPolicyFinding{
				Actual:  string(level),
				Gap:     "admissionregistration.k8s.io/mutatingwebhookconfigurations create",
				Message: fmt.Sprintf("webhook configuration changes logged at '%s'; admission bypass attacks may be invisible", level),
			}
		}
		return nil
	},
}

// AllAuditPolicyRules returns all AuditPolicy completeness rules (NV5101–NV5106).
func AllAuditPolicyRules() []AuditPolicyRule {
	all := []AuditPolicyRule{
		ruleAuditSecrets,
		ruleAuditPodExec,
		ruleAuditAnonymous,
		ruleAuditCatchAll,
		ruleAuditRBACMutations,
		ruleAuditWebhookMutations,
	}
	for i := range all {
		r := &all[i]
		orig := r.Check
		r.Check = func(policy *audit.Policy) *AuditPolicyFinding {
			f := orig(policy)
			if f != nil {
				f.Rule = r
			}
			return f
		}
	}
	return all
}
