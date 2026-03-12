# NodeVet

Kubernetes kubelet / node / container-runtime security validation CLI.

NodeVet checks the layer **below** your workloads — kubelet configuration, OS-level access controls, container runtime settings, RBAC bindings, audit policy completeness, and version staleness — against the CIS Kubernetes Benchmark and known CVEs.

```
nodevet check   --config /etc/kubernetes/kubelet.yaml
nodevet cluster --all-nodes
nodevet runtime --config /etc/containerd/config.toml
nodevet access  --rbac --pods
nodevet audit   --policy /etc/kubernetes/audit-policy.yaml
nodevet scan    --config kubelet.yaml --rbac --pods --policy audit-policy.yaml
```

---

## Table of Contents

- [Install](#install)
- [Commands](#commands)
  - [check](#check--kubelet-configuration)
  - [cluster](#cluster--live-node-scan)
  - [runtime](#runtime--container-runtime)
  - [access](#access--rbac--pod-risks)
  - [audit](#audit--audit-policy)
  - [scan](#scan--full-compound-scan)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Rule ID taxonomy](#rule-id-taxonomy)
- [Development](#development)

---

## Install

```bash
git clone https://github.com/NodeVet/nodevet
cd nodevet
make build          # → bin/nodevet
make ci             # vet + test + build
```

**Requirements:** Go 1.22+, `kubectl`/kubeconfig for live cluster commands.

---

## Commands

### `check` — Kubelet configuration

Evaluates kubelet authentication, TLS, and pod-control settings (NV1xxx rules).

```bash
# From a KubeletConfiguration YAML file
nodevet check --config /etc/kubernetes/kubelet.yaml

# From raw startup flags
nodevet check --flags "--anonymous-auth=false --tls-cert-file=/etc/k8s/kubelet.crt"

# From a live node via /configz API
nodevet check --node my-node-name

# Combine: static config + live config → also reports config drift
nodevet check --config kubelet.yaml --node my-node-name
```

| Flag | Description |
|------|-------------|
| `--config` | Path to `KubeletConfiguration` YAML |
| `--flags` | Raw kubelet startup flags string |
| `--node` | Node name; fetches live config via `/proxy/configz` |
| `--kubeconfig` | Path to kubeconfig (default: `$KUBECONFIG` or `~/.kube/config`) |

**Config drift detection:** When both `--config`/`--flags` and `--node` are given, NodeVet compares the static desired config against the live running config and reports any discrepancies as `CRITICAL: config drift`.

---

### `cluster` — Live node scan

Fetches node objects from the cluster and runs node-level checks (NV3xxx, NV4xxx, NV7xxx).

```bash
nodevet cluster --all-nodes
nodevet cluster --node gke-my-cluster-pool-abc123
nodevet cluster --context staging --kubeconfig ~/.kube/staging.yaml
```

| Flag | Description |
|------|-------------|
| `--all-nodes` | Scan every node in the cluster |
| `--node` | Scan a single named node |
| `--context` | Kubernetes context name |
| `--kubeconfig` | Path to kubeconfig |

**Checks include:**
- Node conditions (`Ready`, `MemoryPressure`, `DiskPressure`) — NV3001–NV3003
- Kubernetes version staleness / EOL — NV7001
- containerd version CVEs — NV7002
- Linux kernel container-escape CVEs — NV7003
- GKE: Shielded Nodes, Secure Boot, vTPM, Workload Identity, Binary Authorization, OS Login — NV4001–NV4006, NV3201–NV3202
- EKS: IMDSv2, EBS encryption, AMI auto-update — NV4101–NV4103
- AKS: Defender for Containers, disk encryption — NV4201–NV4202

---

### `runtime` — Container runtime

Evaluates containerd `config.toml` and cluster `RuntimeClass` objects (NV2xxx rules).

```bash
nodevet runtime --config /etc/containerd/config.toml
nodevet runtime --runtimeclass
nodevet runtime --config /etc/containerd/config.toml --runtimeclass
```

| Flag | Description |
|------|-------------|
| `--config` | Path to containerd `config.toml` |
| `--runtimeclass` | Check `RuntimeClass` objects in the cluster |
| `--kubeconfig` | Path to kubeconfig (for `--runtimeclass`) |
| `--context` | Kubernetes context (for `--runtimeclass`) |

**Checks include:**
- `enable_unprivileged_ports` / `enable_unprivileged_icmp` — NV2001, NV2002
- Snapshotter safety (`devmapper`, `fuse-overlayfs`) — NV2003
- Insecure registry mirrors — NV2004
- `restrict_oci_annotations` — NV2005
- Default seccomp profile — NV2006
- Rootless containerd — NV2007
- RuntimeClass sandboxing (gVisor / Kata) — NV2101, NV2102

---

### `access` — RBAC & pod risks

Checks kube-apiserver authorization settings, RBAC bindings granting node/pod access, and risky pod configurations (NV3101–NV3305 rules).

```bash
# Check apiserver authorization flags
nodevet access --apiserver-flags "--authorization-mode=Node,RBAC --enable-admission-plugins=NodeRestriction"

# Scan RBAC bindings for dangerous nodes/proxy and pods/exec grants
nodevet access --rbac

# Scan running pods for privileged / hostPID / hostPath risks
nodevet access --pods

# Both together
nodevet access --rbac --pods
```

| Flag | Description |
|------|-------------|
| `--apiserver-flags` | Raw kube-apiserver startup flags |
| `--apiserver-config` | Path to kube-apiserver config YAML |
| `--rbac` | Scan ClusterRoles/Roles for dangerous bindings |
| `--pods` | Scan running pods for host-namespace / privileged risks |
| `--kubeconfig` | Path to kubeconfig |
| `--context` | Kubernetes context |

**Risk weighting:** Bindings to `system:authenticated`, `system:unauthenticated`, or `system:serviceaccounts` are escalated to `CRITICAL`. System roles (`system:*`, `cluster-admin`) and system namespaces (`kube-system`, `kube-public`, `kube-node-lease`) are excluded from pod findings to reduce false positives.

---

### `audit` — Audit policy

Validates kube-apiserver audit log flags and `AuditPolicy` YAML completeness (NV5xxx rules).

```bash
# Check apiserver audit log flags
nodevet audit --apiserver-flags "--audit-log-path=/var/log/audit.log --audit-log-maxage=30"

# Check AuditPolicy YAML for coverage gaps
nodevet audit --policy /etc/kubernetes/audit-policy.yaml

# Emit a recommended AuditPolicy to stdout
nodevet audit --emit-policy > /etc/kubernetes/recommended-audit-policy.yaml
```

| Flag | Description |
|------|-------------|
| `--apiserver-flags` | Raw kube-apiserver startup flags |
| `--apiserver-config` | Path to kube-apiserver config YAML |
| `--policy` | Path to `AuditPolicy` YAML to evaluate |
| `--emit-policy` | Print recommended `AuditPolicy` and exit |

**Policy completeness checks** (NV5101–NV5107):
- Secrets access (get/list/watch) is audited
- `pods/exec` and `pods/attach` are audited
- `system:anonymous` actions are audited
- Catch-all `ResponseComplete` level rule present
- RBAC mutations audited
- Webhook calls audited
- No broadly-suppressing `None` rule shadows earlier specific rules (NV5107)

When a finding is shadowed by a `None` rule, the output shows `(matched by rule #N)` so you can locate the exact AuditPolicy entry to fix.

---

### `scan` — Full compound scan

Runs all sub-checks together and correlates findings into compound attack-path findings (C001–C005).

```bash
nodevet scan \
  --config /etc/kubernetes/kubelet.yaml \
  --apiserver-flags "--authorization-mode=Node,RBAC" \
  --rbac --pods \
  --policy /etc/kubernetes/audit-policy.yaml
```

| Flag | Description |
|------|-------------|
| `--config` | Path to KubeletConfiguration YAML |
| `--flags` | Raw kubelet startup flags |
| `--node` | Node name for live config fetch |
| `--apiserver-flags` | Raw kube-apiserver startup flags |
| `--rbac` | Scan RBAC bindings |
| `--pods` | Scan running pods |
| `--policy` | Path to AuditPolicy YAML |
| `--kubeconfig` | Path to kubeconfig |
| `--context` | Kubernetes context |

**Compound correlation rules:**

| ID | Trigger | Severity |
|----|---------|----------|
| C001 | `pods/exec` RBAC grant (NV3302) + exec not audited (NV5102) | CRITICAL |
| C002 | kubelet anonymous-auth (NV1001) + broad exec grant (NV3302) | CRITICAL |
| C003 | node-escape pod (NV3305: hostPID+privileged) + no exec audit (NV5102) | CRITICAL |
| C004 | AlwaysAllow auth (NV1002) + broad nodes/proxy grant (NV3301) | CRITICAL |
| C005 | Privileged pod (NV3304) + exec not audited (NV5102) | HIGH |

---

## Output formats

All commands accept `--format` at the root level:

```bash
nodevet --format json check --config kubelet.yaml
nodevet --format json access --rbac --pods
nodevet --format json audit --policy audit-policy.yaml
```

Default is `tty` (coloured table output). JSON output is structured and suitable for piping to `jq` or SIEM ingestion.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings |
| `1` | One or more `CRITICAL` or `HIGH` findings |
| `2` | Only `MEDIUM` or `LOW` findings (no `CRITICAL`/`HIGH`) |

---

## Rule ID taxonomy

```
NV1xxx   kubelet configuration (auth, TLS, pod controls)
NV2xxx   container runtime (containerd config, RuntimeClass)
NV3xxx   OS / node access control (RBAC, SSH, pod risks)
NV4xxx   managed cluster platform (GKE / EKS / AKS)
NV5xxx   audit log configuration and AuditPolicy completeness
NV6xxx   eBPF / runtime security (Falco, Tetragon, Cilium)
NV7xxx   version staleness (Kubernetes, containerd, Linux kernel)
Cxxx     compound attack-path correlations (from nodevet scan)
```

### Severity levels

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Immediate exploitation risk; fix before any other work |
| `HIGH` | Significant security gap; remediate promptly |
| `MEDIUM` | Notable risk; address in next maintenance window |
| `LOW` | Best-practice deviation; low exploitation potential |

---

## Development

```bash
make build         # compile → bin/nodevet
make test          # go test -race -cover ./...
make vet           # go vet ./...
make ci            # vet + test + build
```

### Adding a new rule

**Kubelet / apiserver rule (NV1xxx / NV5xxx):**

1. Add a `Rule` variable in the appropriate file under `internal/rules/` (e.g. `kubelet_auth.go`).
2. Register it in `All()` / `AllAPIServerRules()` / `AllAuditFlagRules()` in the corresponding `*_registry.go`.

**Node rule (NV3xxx / NV4xxx / NV7xxx):**

1. Add a `NodeRule` variable in `internal/rules/`.
2. Register it in `AllNodeRules()` in `internal/rules/node_registry.go`.
3. Populate any required fields in `NodeInfo` from `node.Status.NodeInfo` in `internal/node/platform.go`.

**Access rule (NV3xxx RBAC/pod):**

1. Add a function returning `[]AccessFinding` in `internal/rules/access_rbac.go`.
2. Register it in `AllAccessRules()`.
3. For per-finding severity overrides, set `SeverityOverride *Severity` on the `AccessFinding`.

**Audit policy rule (NV5xxx):**

1. Add a function returning `[]AuditPolicyFinding` in `internal/rules/audit_policy.go`.
2. Register it in `AllAuditPolicyRules()`.
3. Use `policy.FindLevelWithIndex()` (not `FindLevel()`) when you need to detect first-match shadowing.

**Correlation rule (Cxxx):**

1. Add a `rule` entry to `allRules` in `internal/correlate/correlate.go`.
2. Add a test case to `internal/correlate/correlate_test.go`.

### Key design patterns

- **Config sources are merged left-to-right:** later sources win. `Merge()` in `internal/source/source.go`.
- **First-match AuditPolicy semantics:** use `FindLevelWithIndex` to expose which rule index matched so findings can cite it.
- **SeverityOverride:** `AccessFinding` and `NodeFinding` both support a per-finding severity override; always call `EffectiveSeverity()` in renderers and checkers rather than `Rule.Severity` directly.
- **System namespace / system role filtering:** `access.SystemNamespaces` and the `system:*` / `cluster-admin` skip logic in `access_rbac.go` keep false-positive rates low. Extend these rather than working around them.
