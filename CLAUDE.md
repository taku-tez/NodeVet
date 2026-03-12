# NodeVet — AI Agent Guide

This file gives an AI coding assistant the context needed to work effectively on NodeVet without repeatedly re-reading the entire codebase.

## What this project is

NodeVet is a Go CLI tool (`github.com/NodeVet/nodevet`) that validates the **node layer** of a Kubernetes cluster: kubelet configuration, container runtime, RBAC bindings, audit policy, and version staleness. It is intentionally scoped to the node/runtime layer; workload/manifest checks belong to a separate tool (ManifestVet).

## Repository layout

```
cmd/nodevet/main.go          entry point (calls cli.Execute)
cli/                         one file per subcommand
  root.go                    --format flag, command registration
  check.go                   nodevet check   (kubelet config)
  cluster.go                 nodevet cluster (live node scan)
  runtime.go                 nodevet runtime (containerd / RuntimeClass)
  access.go                  nodevet access  (RBAC + pod risks)
  audit.go                   nodevet audit   (AuditPolicy)
  scan.go                    nodevet scan    (all-in-one + correlation)

internal/
  rules/                     all rule definitions + registries
    rule.go                  Rule, Finding, Result types
    node_rule.go             NodeRule, NodeFinding, NodeResult types
    access_rbac.go           AccessRule, AccessFinding + NV3101-NV3305
    audit_policy.go          AuditPolicyRule, AuditPolicyFinding + NV5101-NV5107
    tls.go                   TLS cipher suite rules (NV1103)
    node_conditions.go       NV3001-NV3003
    node_version.go          NV7001-NV7003 (version staleness)
    *_registry.go            All(), AllNodeRules(), AllAccessRules(), etc.

  source/                    ConfigSource abstraction
    source.go                YAML, flags, configz, TOML sources + Merge/Discrepancy
  checker/                   checkers (one per result type)
  node/                      NodeInfo struct + collector + platform detection
  access/                    RBACCollector + PodCollector + types
  audit/                     AuditPolicy loader + RecommendedPolicy
  correlate/                 Compound attack-path correlations (C001-C005)
  render/                    Table + JSON renderers (one file per result type)
  runtime/                   RuntimeClass collector
  ebpf/                      eBPF/Falco/Tetragon checks (NV6xxx)
```

## How rules work

### Kubelet / apiserver rules (Rule)

```go
// internal/rules/rule.go
type Rule struct {
    ID, Title, Description, Remediation string
    Severity Severity  // CRITICAL | HIGH | MEDIUM | LOW
    Check func(key, value string) *Finding
}
```

- `Check` receives a flat key→value map merged from all ConfigSources.
- Return `nil` for pass, `&Finding{...}` for fail.
- Register in `All()` / `AllAPIServerRules()` / `AllAuditFlagRules()` in `*_registry.go`.

### Node rules (NodeRule)

```go
// internal/rules/node_rule.go
type NodeRule struct {
    ID, Title, Description, Remediation string
    Severity Severity
    Platform node.Platform  // empty = all platforms
    Check func(n *node.NodeInfo) *NodeFinding
}

type NodeFinding struct {
    Rule             *NodeRule
    Node, Actual, Message string
    SeverityOverride *Severity  // overrides Rule.Severity when set
}
```

- `EffectiveSeverity()` on `NodeFinding` returns the override if set, else `Rule.Severity`.
- Always call `f.EffectiveSeverity()` in renderers and checkers — never `f.Rule.Severity` directly.
- Register in `AllNodeRules()` in `node_registry.go`.
- Populate new `NodeInfo` fields from `node.Status.NodeInfo` in `internal/node/platform.go:FromK8sNode`.

### Access rules (AccessFinding)

```go
// internal/rules/access_rbac.go
type AccessFinding struct {
    Rule             *AccessRule
    Subject, Namespace, RoleName, Message string
    SeverityOverride *Severity
}
```

- `EffectiveSeverity()` works the same way.
- Escalate to CRITICAL when subject is `system:authenticated`, `system:unauthenticated`, or `system:serviceaccounts`.
- **Skip** roles with prefix `system:` or name `cluster-admin` to avoid false positives.
- Register in `AllAccessRules()`.

### Audit policy rules (AuditPolicyFinding)

```go
type AuditPolicyFinding struct {
    Rule               *AuditPolicyRule
    Message, Remediation string
    ShadowingRuleIndex int  // 1-based index of the rule that shadowed this (0 = not shadowed)
}
```

- Use `policy.FindLevelWithIndex(op)` (not `FindLevel`) to get both the matched level and which rule index matched.
- Use `policy.IsBroadSuppressor(i)` to detect a `level:None` rule with no constraints at index `i`.
- Register in `AllAuditPolicyRules()`.

### Correlation rules (correlate.Finding)

```go
// internal/correlate/correlate.go
type rule struct {
    ID, Title, Message, Remediation string
    Severity    rules.Severity
    RequiredIDs []string  // all rule IDs must be present in fired set
}
```

- `Correlate(firedIDs []string)` checks every rule; if all `RequiredIDs` fired, a `Finding` is emitted.
- `nodevet scan` collects fired IDs across all checkers and passes them to `Correlate`.
- Add test cases to `correlate_test.go` for every new rule.

## Config sources

```go
source.NewYAMLSource(path)          // KubeletConfiguration YAML
source.NewFlagSource(flagsStr)      // "--key=value --key2=value2"
source.NewConfigzSource(node, kc)   // live /proxy/configz fetch
source.NewContainerdSource(path)    // containerd config.toml (TOML)
```

Multiple sources are merged left-to-right with `source.Merge(maps...)` — later sources win.
`source.FindDiscrepancies(static, live)` returns keys where static ≠ live.

## Severity constants

```go
rules.SeverityCritical  // "CRITICAL"
rules.SeverityHigh      // "HIGH"
rules.SeverityMedium    // "MEDIUM"
rules.SeverityLow       // "LOW"

rules.SeverityIsHighOrAbove(sev) bool  // true for CRITICAL and HIGH
```

Exit code 1 = any CRITICAL/HIGH finding. Exit code 2 = only MEDIUM/LOW findings.

## Output / rendering

Each result type has a dedicated renderer pair (table + JSON):

| Result type | Table renderer | JSON writer |
|-------------|---------------|-------------|
| `*rules.Result` | `render.New(w).Render(result)` | `render.WriteCheckerJSON(w, result)` |
| `*rules.NodeResult` | `render.NewNodeRenderer(w).RenderNodes(result)` | `render.WriteNodeJSON(w, result)` |
| `*rules.AccessResult` | `render.NewAccessRenderer(w).RenderAccess(result)` | `render.WriteAccessJSON(w, result)` |
| `*rules.AuditPolicyResult` | `render.NewAuditRenderer(w).RenderAudit(result)` | `render.WriteAuditJSON(w, result)` |
| `[]correlate.Finding` | `render.RenderCorrelations(w, findings)` | (included in scan JSON) |

Table renderers call `colorBySeverity(sev, id, sevStr)` only when `isTerminalOutput(w)` is true.

## Rule ID ranges

```
NV1001-NV1204   kubelet: auth/authz, TLS, pod controls
NV2001-NV2102   container runtime: containerd config, RuntimeClass
NV3001-NV3003   node conditions
NV3101-NV3102   kube-apiserver node authorization
NV3201-NV3202   SSH / OS access (GKE)
NV3301-NV3305   RBAC and pod access risks
NV4001-NV4006   GKE-specific node checks
NV4101-NV4103   EKS-specific node checks
NV4201-NV4202   AKS-specific node checks
NV5001-NV5006   kube-apiserver audit log flags
NV5101-NV5107   AuditPolicy completeness
NV6001-NV6202   eBPF / runtime security (Falco, Tetragon, Cilium)
NV7001-NV7003   version staleness (Kubernetes, containerd, kernel)
C001-C005       compound attack-path correlations
```

## Testing conventions

- Unit tests live next to the package they test (`_test.go` in the same package).
- Run: `make test` (= `go test -race -cover ./...`).
- Correlation tests in `internal/correlate/correlate_test.go` use rule ID strings — update them when adding C-rules.
- Version rule tests in `internal/rules/node_version_test.go` cover all threshold boundary conditions.
- Access rule tests in `internal/rules/access_rbac_test.go` must verify system role skipping and dangerous-subject escalation.

## Common pitfalls

- **Don't call `f.Rule.Severity` directly** in renderers or checkers — use `f.EffectiveSeverity()`. Failing to do so silently ignores per-finding severity overrides.
- **AuditPolicy first-match semantics:** a broadly-suppressing `None` rule early in the policy silently prevents later rules from matching. Use `FindLevelWithIndex` + `IsBroadSuppressor` to detect this (NV5107).
- **System namespace filtering:** `access.SystemNamespaces` holds the skip list. Pod risks in `kube-system`, `kube-public`, `kube-node-lease` are expected and excluded by default.
- **RBAC system role skip:** roles named `cluster-admin` or with prefix `system:` are intentional and should not be flagged by NV3301/NV3302.
- **ConfigSource Merge order matters:** later maps win. The discrepancy check compares the merged static map against the live configz map.
