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
		ruleAuditBroadSuppressor,
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

func TestAuditBroadSuppressor(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantHit bool
	}{
		{
			"no suppressor",
			`rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
  - level: Metadata`,
			false,
		},
		{
			"broad None at end (no rules after, harmless)",
			`rules:
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]
  - level: None`,
			false,
		},
		{
			"broad None before other rules",
			`rules:
  - level: None
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]`,
			true,
		},
		{
			"targeted None (specific resource) is not a suppressor",
			`rules:
  - level: None
    resources:
      - group: "coordination.k8s.io"
        resources: ["leases"]
  - level: RequestResponse
    resources:
      - group: ""
        resources: ["secrets"]`,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := audit.ParsePolicy([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("ParsePolicy: %v", err)
			}
			f := ruleAuditBroadSuppressor.Check(p)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestAuditFindingShadowingRuleIndex(t *testing.T) {
	// A catch-all None rule at position 1 (index 0) should surface as ShadowingRuleIndex=1
	yaml := `rules:
  - level: None`
	p, err := audit.ParsePolicy([]byte(yaml))
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}
	f := ruleAuditSecrets.Check(p)
	if f == nil {
		t.Fatal("expected finding for None-only policy")
	}
	if f.ShadowingRuleIndex != 1 {
		t.Errorf("ShadowingRuleIndex: got %d, want 1", f.ShadowingRuleIndex)
	}
}
