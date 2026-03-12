package audit

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Level represents an audit level in order of increasing verbosity.
type Level string

const (
	LevelNone            Level = "None"
	LevelMetadata        Level = "Metadata"
	LevelRequest         Level = "Request"
	LevelRequestResponse Level = "RequestResponse"
)

// levelRank maps a Level to its ordinal for comparison.
var levelRank = map[Level]int{
	LevelNone:            0,
	LevelMetadata:        1,
	LevelRequest:         2,
	LevelRequestResponse: 3,
}

// AtLeast returns true if l >= minimum.
func (l Level) AtLeast(minimum Level) bool {
	return levelRank[l] >= levelRank[minimum]
}

// GroupResource describes a resource group and set of resource types.
type GroupResource struct {
	Group     string   `yaml:"group"`
	Resources []string `yaml:"resources"`
}

// PolicyRule is one rule in an AuditPolicy.
type PolicyRule struct {
	Level      Level           `yaml:"level"`
	Users      []string        `yaml:"users"`
	UserGroups []string        `yaml:"userGroups"`
	Verbs      []string        `yaml:"verbs"`
	Resources  []GroupResource `yaml:"resources"`
	Namespaces []string        `yaml:"namespaces"`
	// OmitStages omitted for simplicity
}

// Policy is the parsed AuditPolicy.
type Policy struct {
	Rules []PolicyRule `yaml:"rules"`
}

// AuditOperation describes a specific API operation to look up in the policy.
type AuditOperation struct {
	User        string
	UserGroup   string
	Verb        string
	Group       string
	Resource    string
	Subresource string
	Namespace   string
}

// FindLevel returns the Level that would be applied to the given operation,
// following Kubernetes AuditPolicy first-match semantics.
func (p *Policy) FindLevel(op AuditOperation) Level {
	l, _ := p.FindLevelWithIndex(op)
	return l
}

// FindLevelWithIndex returns the Level and the 0-based index of the matching rule.
// Returns (LevelNone, -1) if no rule matched.
func (p *Policy) FindLevelWithIndex(op AuditOperation) (Level, int) {
	for i, rule := range p.Rules {
		if ruleMatches(rule, op) {
			return rule.Level, i
		}
	}
	return LevelNone, -1
}

// IsBroadSuppressor returns true if the rule at index i is a broadly-suppressing
// None rule (no specific resource, user, or verb constraints) that could shadow
// specific security rules placed after it.
func (p *Policy) IsBroadSuppressor(i int) bool {
	if i < 0 || i >= len(p.Rules) {
		return false
	}
	r := p.Rules[i]
	return r.Level == LevelNone &&
		len(r.Resources) == 0 &&
		len(r.Users) == 0 &&
		len(r.UserGroups) == 0 &&
		len(r.Verbs) == 0 &&
		len(r.Namespaces) == 0
}

func ruleMatches(rule PolicyRule, op AuditOperation) bool {
	// Users: if rule specifies users, op.User must be in the list.
	// An empty op.User never matches a rule with specific user constraints.
	if len(rule.Users) > 0 {
		if !containsOrWild(rule.Users, op.User) {
			return false
		}
	}
	// UserGroups: if rule specifies groups, op.UserGroup must be in the list.
	// An empty op.UserGroup never matches a rule with specific group constraints.
	if len(rule.UserGroups) > 0 {
		if !containsOrWild(rule.UserGroups, op.UserGroup) {
			return false
		}
	}
	// Verbs: if non-empty, op.Verb must match one
	if len(rule.Verbs) > 0 && op.Verb != "" {
		if !containsOrWild(rule.Verbs, op.Verb) {
			return false
		}
	}
	// Namespaces: if non-empty, op.Namespace must match
	if len(rule.Namespaces) > 0 && op.Namespace != "" {
		if !containsOrWild(rule.Namespaces, op.Namespace) {
			return false
		}
	}
	// Resources: if non-empty, (group, resource) must match
	if len(rule.Resources) > 0 && op.Resource != "" {
		matched := false
		for _, gr := range rule.Resources {
			if groupMatches(gr.Group, op.Group) && resourceMatches(gr.Resources, op.Resource) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func containsOrWild(list []string, target string) bool {
	for _, item := range list {
		if item == "*" || item == target {
			return true
		}
	}
	return false
}

func groupMatches(ruleGroup, opGroup string) bool {
	return ruleGroup == "" || ruleGroup == "*" || ruleGroup == opGroup
}

func resourceMatches(ruleResources []string, opResource string) bool {
	for _, r := range ruleResources {
		if r == "*" || r == opResource {
			return true
		}
	}
	return false
}

// LoadPolicy reads and parses an AuditPolicy YAML file.
func LoadPolicy(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading audit policy %s: %w", path, err)
	}
	return ParsePolicy(data)
}

// ParsePolicy parses AuditPolicy YAML bytes.
func ParsePolicy(data []byte) (*Policy, error) {
	var wrapper struct {
		Rules []PolicyRule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("parsing audit policy: %w", err)
	}
	return &Policy{Rules: wrapper.Rules}, nil
}
