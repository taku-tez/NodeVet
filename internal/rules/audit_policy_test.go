package rules

import (
	"testing"

	"github.com/NodeVet/nodevet/internal/audit"
)

func loadTestPolicy(t *testing.T, path string) *audit.Policy {
	t.Helper()
	p, err := audit.LoadPolicy(path)
	if err != nil {
		t.Fatalf("LoadPolicy(%s): %v", path, err)
	}
	return p
}

func TestAuditPolicyRules_Complete(t *testing.T) {
	policy := loadTestPolicy(t, "../audit/testdata/policy-complete.yaml")

	rules := []AuditPolicyRule{
		ruleAuditSecrets,
		ruleAuditPodExec,
		ruleAuditAnonymous,
		ruleAuditCatchAll,
		ruleAuditRBACMutations,
		ruleAuditWebhookMutations,
	}
	for _, rule := range rules {
		t.Run(rule.ID, func(t *testing.T) {
			f := rule.Check(policy)
			if f != nil {
				t.Errorf("%s: unexpected finding: %s (actual level: %s)", rule.ID, f.Message, f.Actual)
			}
		})
	}
}

func TestAuditPolicyRules_Incomplete(t *testing.T) {
	policy := loadTestPolicy(t, "../audit/testdata/policy-incomplete.yaml")

	// All critical rules should fire on the incomplete policy
	mustFire := []AuditPolicyRule{
		ruleAuditSecrets,
		ruleAuditPodExec,
		ruleAuditAnonymous,
		ruleAuditCatchAll,
		ruleAuditRBACMutations,
		ruleAuditWebhookMutations,
	}
	for _, rule := range mustFire {
		t.Run(rule.ID, func(t *testing.T) {
			f := rule.Check(policy)
			if f == nil {
				t.Errorf("%s: expected finding for incomplete policy, got nil", rule.ID)
			}
		})
	}
}
