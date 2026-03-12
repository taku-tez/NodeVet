package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/NodeVet/nodevet/internal/node"
)

// parseMinorVersion extracts (major, minor) from strings like "v1.29.3" or "1.29.3".
// Returns (0, 0, false) if parsing fails.
func parseMinorVersion(v string) (major, minor int, ok bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return 0, 0, false
	}
	maj, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, false
	}
	min, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, false
	}
	return maj, min, true
}

// parsePatchVersion extracts (major, minor, patch) from strings like "v1.29.3" or "1.7.9".
func parsePatchVersion(v string) (major, minor, patch int, ok bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 3 {
		return 0, 0, 0, false
	}
	// Strip pre-release/build suffixes from patch (e.g. "9-ubuntu1" → "9")
	patchField := strings.FieldsFunc(parts[2], func(r rune) bool {
		return r == '-' || r == '+'
	})
	if len(patchField) == 0 {
		return 0, 0, 0, false
	}
	maj, err1 := strconv.Atoi(parts[0])
	min, err2 := strconv.Atoi(parts[1])
	pat, err3 := strconv.Atoi(patchField[0])
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0, false
	}
	return maj, min, pat, true
}

// --- NV7001: Kubernetes version staleness ---

// k8sEOLMinorVersion: Kubernetes minor < this is end-of-life (no security patches).
// k8sStaleMinorVersion: Kubernetes minor < this is stale (2+ releases behind).
// Update these as new releases ship. As of early 2026, 1.29 is EOL, 1.31+ is supported.
const k8sEOLMinorVersion = 29
const k8sStaleMinorVersion = 31

var ruleK8sVersionStaleness = NodeRule{
	ID:          "NV7001",
	Title:       "Kubernetes version is outdated",
	Severity:    SeverityHigh,
	Description: "Running an end-of-life or significantly outdated Kubernetes version means known CVEs may not receive patches.",
	Remediation: "Upgrade to a supported Kubernetes release. See https://kubernetes.io/releases/ for the current support window.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.KubernetesVersion == "" {
			return nil
		}
		_, minor, ok := parseMinorVersion(n.KubernetesVersion)
		if !ok {
			return nil
		}
		var sev Severity
		var msg string
		switch {
		case minor < k8sEOLMinorVersion:
			sev = SeverityCritical
			msg = fmt.Sprintf(
				"Kubernetes %s is end-of-life (minor < 1.%d). No security patches are available. "+
					"Known CVEs on this version will not be fixed upstream.",
				n.KubernetesVersion, k8sEOLMinorVersion)
		case minor < k8sStaleMinorVersion:
			sev = SeverityHigh
			msg = fmt.Sprintf(
				"Kubernetes %s is 2+ releases behind the current stable branch (1.%d+). "+
					"Security patches may be delayed or unavailable.",
				n.KubernetesVersion, k8sStaleMinorVersion)
		default:
			return nil
		}
		return &NodeFinding{
			Message:          msg,
			SeverityOverride: &sev,
		}
	},
}

// --- NV7002: containerd version with known CVEs ---

// containerdVulnRange describes a (major.minor.x) series where fixedPatch is the first safe patch.
type containerdVulnRange struct {
	major      int
	minor      int
	fixedPatch int
	cves       string
}

// containerdVulnRanges: update as new CVEs are disclosed.
var containerdVulnRanges = []containerdVulnRange{
	// 1.6.x: 1.6.27 fixes CVE-2023-25173 and CVE-2024-21626
	{1, 6, 27, "CVE-2023-25173, CVE-2024-21626"},
	// 1.7.x: 1.7.14 fixes CVE-2023-29401 and CVE-2024-21626
	{1, 7, 14, "CVE-2023-29401, CVE-2024-21626"},
}

var ruleContainerdCVE = NodeRule{
	ID:          "NV7002",
	Title:       "containerd version has known CVEs",
	Severity:    SeverityHigh,
	Description: "The node is running a containerd version that has unpatched security vulnerabilities.",
	Remediation: "Upgrade containerd to the latest patch release in your minor series (1.6.x → ≥1.6.27, 1.7.x → ≥1.7.14).",
	Check: func(n *node.NodeInfo) *NodeFinding {
		rtv := n.ContainerRuntimeVersion
		if rtv == "" {
			return nil
		}
		// Runtime version format: "containerd://1.7.9"
		rtv = strings.TrimPrefix(rtv, "containerd://")
		maj, min, pat, ok := parsePatchVersion(rtv)
		if !ok {
			return nil
		}
		for _, r := range containerdVulnRanges {
			if maj == r.major && min == r.minor && pat < r.fixedPatch {
				sev := SeverityHigh
				return &NodeFinding{
					Message: fmt.Sprintf(
						"containerd %s is vulnerable to %s. "+
							"Upgrade to %d.%d.%d or later.",
						n.ContainerRuntimeVersion, r.cves, r.major, r.minor, r.fixedPatch),
					SeverityOverride: &sev,
				}
			}
		}
		return nil
	},
}

// --- NV7003: Linux kernel version with container escape CVEs ---

type kernelThreshold struct {
	major    int
	minor    int
	severity Severity
	cves     string
}

// kernelThresholds: kernels below (major.minor) are flagged.
// Distros often backport patches; the message notes this caveat.
var kernelThresholds = []kernelThreshold{
	// < 4.19: multiple namespace escape CVEs, completely unmaintained upstream
	{4, 19, SeverityCritical, "CVE-2017-5123, CVE-2018-18955, CVE-2019-5736 (runc)"},
	// < 5.4: CVE-2022-0185 (heap overflow in legacy_parse_param), CVE-2021-22555
	{5, 4, SeverityHigh, "CVE-2022-0185, CVE-2021-22555"},
	// < 5.15: CVE-2022-2588 (route4 UAF), CVE-2022-27666
	{5, 15, SeverityMedium, "CVE-2022-2588, CVE-2022-27666"},
}

var ruleKernelCVE = NodeRule{
	ID:          "NV7003",
	Title:       "Linux kernel version has container escape CVEs",
	Severity:    SeverityMedium,
	Description: "The node's Linux kernel version is associated with known container escape or privilege escalation vulnerabilities.",
	Remediation: "Upgrade the node's OS kernel. Cloud providers offer node image updates that include the latest security patches.",
	Check: func(n *node.NodeInfo) *NodeFinding {
		if n.KernelVersion == "" {
			return nil
		}
		// Strip distro suffix: "5.15.0-101-generic" → "5.15.0"
		v := n.KernelVersion
		if idx := strings.Index(v, "-"); idx != -1 {
			v = v[:idx]
		}
		// parsePatchVersion needs at least 3 components
		if strings.Count(v, ".") < 2 {
			v += ".0"
		}
		maj, min, _, ok := parsePatchVersion(v)
		if !ok {
			return nil
		}
		for _, t := range kernelThresholds {
			if maj < t.major || (maj == t.major && min < t.minor) {
				sev := t.severity
				return &NodeFinding{
					Message: fmt.Sprintf(
						"Kernel %s is below %d.%d and may be vulnerable to container escape CVEs (%s). "+
							"Note: distributions often backport patches; verify with your OS vendor.",
						n.KernelVersion, t.major, t.minor, t.cves),
					SeverityOverride: &sev,
				}
			}
		}
		return nil
	},
}
