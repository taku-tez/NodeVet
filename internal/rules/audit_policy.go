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
	Rule                *AuditPolicyRule
	Actual              string
	Message             string
	Gap                 string // description of what is not being logged
	ShadowingRuleIndex  int    // 1-based index of the rule causing the gap (0 = unknown/no match)
}

// AuditPolicyResult holds all AuditPolicy findings.
type AuditPolicyResult struct {
	Findings []*AuditPolicyFinding
	Passed   int
	Errors   int
	Warnings int
}

// shadowMsg returns a suffix string indicating which rule (1-based) is causing the issue.
func shadowMsg(idx int) string {
	if idx >= 0 {
		return fmt.Sprintf(" (matched by rule #%d)", idx+1)
	}
	return " (no matching rule; default is None)"
}

// NV5101: Secrets must be logged at RequestResponse level
var ruleAuditSecrets = AuditPolicyRule{
	ID:          "NV5101",
	Title:       "AuditPolicy: Secrets access must be logged at RequestResponse level",
	Severity:    SeverityHigh,
	Description: "The AuditPolicy does not log Secret reads/writes at RequestResponse level. Credential access will not be captured in audit logs.",
	Remediation: "Add a rule before any catch-all: level: RequestResponse, resources: [{group: \"\", resources: [\"secrets\"]}]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		ops := []audit.AuditOperation{
			{Verb: "get", Group: "", Resource: "secrets"},
			{Verb: "list", Group: "", Resource: "secrets"},
			{Verb: "watch", Group: "", Resource: "secrets"},
		}
		for _, op := range ops {
			level, idx := policy.FindLevelWithIndex(op)
			if !level.AtLeast(audit.LevelRequest) {
				return &AuditPolicyFinding{
					Actual:             string(level),
					Gap:                fmt.Sprintf("secrets/%s", op.Verb),
					Message:            fmt.Sprintf("secrets %s is audited at '%s'%s; expected at least 'Request'", op.Verb, level, shadowMsg(idx)),
					ShadowingRuleIndex: idx + 1,
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
	Severity:    SeverityHigh,
	Description: "The AuditPolicy does not log pod exec/attach requests. Interactive sessions inside containers will not appear in audit logs.",
	Remediation: "Add a rule: level: Request, resources: [{group: \"\", resources: [\"pods/exec\", \"pods/attach\"]}], verbs: [\"create\", \"get\"]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		execOp := audit.AuditOperation{Verb: "create", Group: "", Resource: "pods/exec"}
		level, idx := policy.FindLevelWithIndex(execOp)
		if !level.AtLeast(audit.LevelMetadata) {
			return &AuditPolicyFinding{
				Actual:             string(level),
				Gap:                "pods/exec",
				Message:            fmt.Sprintf("pods/exec is audited at '%s'%s; exec sessions are invisible in audit logs", level, shadowMsg(idx)),
				ShadowingRuleIndex: idx + 1,
			}
		}
		return nil
	},
}

// NV5103: system:anonymous actions must be logged
var ruleAuditAnonymous = AuditPolicyRule{
	ID:          "NV5103",
	Title:       "AuditPolicy: system:anonymous actions must be logged",
	Severity:    SeverityHigh,
	Description: "The AuditPolicy does not log actions by system:anonymous. Unauthenticated probing of the API server will not appear in audit logs.",
	Remediation: "Add a rule: level: RequestResponse, userGroups: [\"system:anonymous\"]",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		op := audit.AuditOperation{UserGroup: "system:anonymous", Verb: "get", Resource: "pods"}
		level, idx := policy.FindLevelWithIndex(op)
		if !level.AtLeast(audit.LevelMetadata) {
			return &AuditPolicyFinding{
				Actual:             string(level),
				Gap:                "system:anonymous",
				Message:            fmt.Sprintf("system:anonymous actions are at level '%s'%s; unauthenticated API access is invisible", level, shadowMsg(idx)),
				ShadowingRuleIndex: idx + 1,
			}
		}
		return nil
	},
}

// NV5104: policy must not default to None for all requests
var ruleAuditCatchAll = AuditPolicyRule{
	ID:          "NV5104",
	Title:       "AuditPolicy: catch-all rule must not be level:None",
	Severity:    SeverityHigh,
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
	Severity:    SeverityMedium,
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
	Severity:    SeverityMedium,
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

// NV5107: broadly-suppressing None rule positioned before critical security rules
var ruleAuditBroadSuppressor = AuditPolicyRule{
	ID:          "NV5107",
	Title:       "AuditPolicy: broadly-suppressing None rule shadows subsequent rules",
	Severity:    SeverityCritical,
	Description: "The AuditPolicy contains a level:None rule with no specific constraints (user, resource, verb). Due to first-match semantics, all rules after it are unreachable and will never be evaluated.",
	Remediation: "Move specific security rules (Secrets, pods/exec, RBAC) before the broad None rule, or replace the broad None with more targeted suppression (e.g. suppress only 'leases' resources).",
	Check: func(policy *audit.Policy) *AuditPolicyFinding {
		for i := range policy.Rules {
			if !policy.IsBroadSuppressor(i) {
				continue
			}
			// Only flag if there are rules after this one (they are unreachable)
			if i < len(policy.Rules)-1 {
				return &AuditPolicyFinding{
					Actual:             fmt.Sprintf("rule #%d: level:None with no constraints", i+1),
					Gap:                fmt.Sprintf("all rules after position #%d are unreachable", i+1),
					Message:            fmt.Sprintf("rule #%d is a broadly-suppressing level:None rule; %d subsequent rule(s) are unreachable due to first-match semantics", i+1, len(policy.Rules)-i-1),
					ShadowingRuleIndex: i + 1,
				}
			}
		}
		return nil
	},
}

// AllAuditPolicyRules returns all AuditPolicy completeness rules (NV5101–NV5107).
func AllAuditPolicyRules() []AuditPolicyRule {
	all := []AuditPolicyRule{
		ruleAuditSecrets,
		ruleAuditPodExec,
		ruleAuditAnonymous,
		ruleAuditCatchAll,
		ruleAuditRBACMutations,
		ruleAuditWebhookMutations,
		ruleAuditBroadSuppressor,
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
