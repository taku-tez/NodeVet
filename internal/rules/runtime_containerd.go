package rules

import "strings"

// containerd rules: NV2001–NV2007

// NV2001: enable_unprivileged_ports should be false
var ruleContainerdUnprivilegedPorts = Rule{
	ID:          "NV2001",
	Title:       "containerd: enable_unprivileged_ports should be disabled",
	Severity:    SeverityMedium,
	Description: "containerd enable_unprivileged_ports=true allows containers to bind to privileged ports (<1024) without elevated capabilities.",
	Remediation: "Set enable_unprivileged_ports = false under [plugins.\"io.containerd.grpc.v1.cri\"] in /etc/containerd/config.toml.",
	Check: func(values map[string]string) *Finding {
		if v := values["runtime.enable-unprivileged-ports"]; v == "true" {
			return &Finding{
				Actual:  "true",
				Message: "enable_unprivileged_ports=true; containers may bind to privileged ports without extra capabilities",
			}
		}
		return nil
	},
}

// NV2002: enable_unprivileged_icmp should be false
var ruleContainerdUnprivilegedICMP = Rule{
	ID:          "NV2002",
	Title:       "containerd: enable_unprivileged_icmp should be disabled",
	Severity:    SeverityMedium,
	Description: "containerd enable_unprivileged_icmp=true allows unprivileged containers to send ICMP packets, enabling potential network probing.",
	Remediation: "Set enable_unprivileged_icmp = false under [plugins.\"io.containerd.grpc.v1.cri\"] in /etc/containerd/config.toml.",
	Check: func(values map[string]string) *Finding {
		if v := values["runtime.enable-unprivileged-icmp"]; v == "true" {
			return &Finding{
				Actual:  "true",
				Message: "enable_unprivileged_icmp=true; containers may send ICMP without NET_RAW capability",
			}
		}
		return nil
	},
}

// NV2003: snapshotter should not be an unsafe value
var ruleContainerdSnapshotter = Rule{
	ID:          "NV2003",
	Title:       "containerd: snapshotter should use a secure driver",
	Severity:    SeverityMedium,
	Description: "containerd snapshotter is not set or uses a non-standard driver. The recommended snapshotter is 'overlayfs'.",
	Remediation: "Set snapshotter = \"overlayfs\" under [plugins.\"io.containerd.grpc.v1.cri\".containerd] in /etc/containerd/config.toml.",
	Check: func(values map[string]string) *Finding {
		snapshotter := values["runtime.snapshotter"]
		// overlayfs and native are considered safe
		safe := map[string]bool{"overlayfs": true, "native": true, "": true}
		if snapshotter != "" && !safe[snapshotter] {
			return &Finding{
				Actual:  snapshotter,
				Message: "snapshotter is not overlayfs; verify the driver is securely configured",
			}
		}
		return nil
	},
}

// NV2004: registry mirrors must use HTTPS endpoints
var ruleContainerdInsecureRegistryMirrors = Rule{
	ID:          "NV2004",
	Title:       "containerd: registry mirrors must use HTTPS endpoints",
	Severity:    SeverityHigh,
	Description: "containerd registry mirror configuration includes HTTP (non-TLS) endpoints. Images pulled from these mirrors are not protected against tampering.",
	Remediation: "Replace http:// registry mirror endpoints with https:// in /etc/containerd/config.toml registry.mirrors configuration.",
	Check: func(values map[string]string) *Finding {
		insecure := values["runtime.insecure-registry-mirrors"]
		if insecure != "" {
			return &Finding{
				Actual:  insecure,
				Message: "registry mirrors contain HTTP endpoints; image pulls are unencrypted and may be tampered with",
			}
		}
		return nil
	},
}

// NV2005: restrict_oci_annotations should be true
var ruleContainerdRestrictOCIAnnotations = Rule{
	ID:          "NV2005",
	Title:       "containerd: restrict_oci_annotations should be enabled",
	Severity:    SeverityMedium,
	Description: "containerd restrict_oci_annotations is not enabled. Containers may use OCI annotations to override security settings.",
	Remediation: "Set restrict_oci_annotations = true under [plugins.\"io.containerd.grpc.v1.cri\"] in /etc/containerd/config.toml.",
	Check: func(values map[string]string) *Finding {
		v := values["runtime.restrict-oci-annotations"]
		if v != "true" {
			actual := v
			if actual == "" {
				actual = "false (default)"
			}
			return &Finding{
				Actual:  actual,
				Message: "restrict_oci_annotations is not enabled; containers may override security settings via OCI annotations",
			}
		}
		return nil
	},
}

// NV2006: default seccomp profile should be configured
var ruleContainerdSeccompProfile = Rule{
	ID:          "NV2006",
	Title:       "containerd: default seccomp profile should be set",
	Severity:    SeverityMedium,
	Description: "containerd default runtime seccomp profile is not explicitly configured. Without a seccomp profile, containers run with the full host syscall table.",
	Remediation: "Configure a default seccomp profile in the containerd runtime options, or ensure kubelet's --seccomp-default flag is set to use RuntimeDefault.",
	Check: func(values map[string]string) *Finding {
		// Check if explicitly set to unconfined or empty
		profile := strings.TrimSpace(values["runtime.seccomp-profile"])
		if profile == "unconfined" {
			return &Finding{
				Actual:  "unconfined",
				Message: "seccomp profile is explicitly set to 'unconfined'; no syscall filtering applied",
			}
		}
		return nil
	},
}

// NV2007: rootless containerd check (informational)
var ruleContainerdRootless = Rule{
	ID:          "NV2007",
	Title:       "containerd: consider running in rootless mode",
	Severity:    SeverityMedium,
	Description: "containerd is running as root (default). Running containerd in rootless mode reduces the blast radius of container escapes.",
	Remediation: "Consider deploying rootless containerd. See: https://github.com/containerd/containerd/blob/main/docs/rootless.md",
	Check: func(values map[string]string) *Finding {
		root := values["runtime.root"]
		// Rootless containerd uses paths under /run/user/<uid>/ or XDG_RUNTIME_DIR
		if root == "" || strings.HasPrefix(root, "/var/lib/") || strings.HasPrefix(root, "/run/containerd") {
			// Running as root
			return &Finding{
				Actual:  rootDisplay(root),
				Message: "containerd root is a system path; running as root increases blast radius of container escapes",
			}
		}
		return nil
	},
}

func rootDisplay(root string) string {
	if root == "" {
		return "/var/lib/containerd (default)"
	}
	return root
}
