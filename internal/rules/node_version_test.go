package rules

import (
	"strings"
	"testing"

	"github.com/NodeVet/nodevet/internal/node"
)

func TestParseMinorVersion(t *testing.T) {
	tests := []struct {
		input      string
		wantMajor  int
		wantMinor  int
		wantOK     bool
	}{
		{"v1.29.3", 1, 29, true},
		{"1.31.0", 1, 31, true},
		{"v1.28.0-eks-abc", 1, 28, true},
		{"", 0, 0, false},
		{"notaversion", 0, 0, false},
	}
	for _, tt := range tests {
		maj, min, ok := parseMinorVersion(tt.input)
		if ok != tt.wantOK || maj != tt.wantMajor || min != tt.wantMinor {
			t.Errorf("parseMinorVersion(%q) = (%d, %d, %v), want (%d, %d, %v)",
				tt.input, maj, min, ok, tt.wantMajor, tt.wantMinor, tt.wantOK)
		}
	}
}

func TestParsePatchVersion(t *testing.T) {
	tests := []struct {
		input string
		maj   int
		min   int
		pat   int
		ok    bool
	}{
		{"1.7.9", 1, 7, 9, true},
		{"v1.6.26", 1, 6, 26, true},
		{"5.15.0", 5, 15, 0, true},
		{"5.15.0-101-generic", 5, 15, 0, true}, // distro suffix stripped by FieldsFunc
		{"1.7", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	}
	for _, tt := range tests {
		maj, min, pat, ok := parsePatchVersion(tt.input)
		if ok != tt.ok || maj != tt.maj || min != tt.min || pat != tt.pat {
			t.Errorf("parsePatchVersion(%q) = (%d, %d, %d, %v), want (%d, %d, %d, %v)",
				tt.input, maj, min, pat, ok, tt.maj, tt.min, tt.pat, tt.ok)
		}
	}
}

func TestK8sVersionStaleness(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantNil bool
		wantSev Severity
		wantMsg string
	}{
		{"current version", "v1.32.0", true, "", ""},
		{"stale but not EOL", "v1.30.1", false, SeverityHigh, "1.31"},
		{"EOL version", "v1.28.5", false, SeverityCritical, "end-of-life"},
		{"very old version", "v1.20.0", false, SeverityCritical, "end-of-life"},
		{"empty version", "", true, "", ""},
		{"unparseable", "notaversion", true, "", ""},
	}

	check := ruleK8sVersionStaleness.Check
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &node.NodeInfo{KubernetesVersion: tt.version}
			f := check(n)
			if tt.wantNil {
				if f != nil {
					t.Errorf("expected nil finding, got: %s", f.Message)
				}
				return
			}
			if f == nil {
				t.Fatal("expected finding, got nil")
			}
			if f.EffectiveSeverity() != tt.wantSev {
				t.Errorf("severity = %s, want %s", f.EffectiveSeverity(), tt.wantSev)
			}
			if tt.wantMsg != "" && !strings.Contains(f.Message, tt.wantMsg) {
				t.Errorf("message %q does not contain %q", f.Message, tt.wantMsg)
			}
		})
	}
}

func TestContainerdCVE(t *testing.T) {
	tests := []struct {
		name    string
		runtime string
		wantNil bool
		wantCVE string
	}{
		{"safe 1.7 version", "containerd://1.7.14", true, ""},
		{"safe 1.6 version", "containerd://1.6.27", true, ""},
		{"vulnerable 1.7.9", "containerd://1.7.9", false, "CVE-2023-29401"},
		{"vulnerable 1.6.20", "containerd://1.6.20", false, "CVE-2023-25173"},
		{"empty runtime", "", true, ""},
		{"not containerd", "docker://20.10.0", true, ""},
		{"safe newer version", "containerd://1.7.20", true, ""},
	}

	check := ruleContainerdCVE.Check
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &node.NodeInfo{ContainerRuntimeVersion: tt.runtime}
			f := check(n)
			if tt.wantNil {
				if f != nil {
					t.Errorf("expected nil finding, got: %s", f.Message)
				}
				return
			}
			if f == nil {
				t.Fatal("expected finding, got nil")
			}
			if tt.wantCVE != "" && !strings.Contains(f.Message, tt.wantCVE) {
				t.Errorf("message %q does not contain %q", f.Message, tt.wantCVE)
			}
		})
	}
}

func TestKernelCVE(t *testing.T) {
	tests := []struct {
		name    string
		kernel  string
		wantNil bool
		wantSev Severity
	}{
		{"safe kernel 6.1", "6.1.0-20-cloud-amd64", true, ""},
		{"safe kernel 5.15", "5.15.0-101-generic", true, ""},
		{"medium 5.10", "5.10.0-28-generic", false, SeverityMedium},
		{"high 4.19.0", "4.19.0-24-cloud", false, SeverityHigh},
		{"critical 4.18", "4.18.0-240.el8.x86_64", false, SeverityCritical},
		{"empty kernel", "", true, ""},
	}

	check := ruleKernelCVE.Check
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &node.NodeInfo{KernelVersion: tt.kernel}
			f := check(n)
			if tt.wantNil {
				if f != nil {
					t.Errorf("expected nil finding, got: %s", f.Message)
				}
				return
			}
			if f == nil {
				t.Fatal("expected finding, got nil")
			}
			if f.EffectiveSeverity() != tt.wantSev {
				t.Errorf("severity = %s, want %s", f.EffectiveSeverity(), tt.wantSev)
			}
		})
	}
}
