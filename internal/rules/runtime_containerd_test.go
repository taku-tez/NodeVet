package rules

import "testing"

func TestContainerdUnprivilegedPorts(t *testing.T) {
	rule := ruleContainerdUnprivilegedPorts
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (safe default)", map[string]string{}, false},
		{"false (secure)", map[string]string{"runtime.enable-unprivileged-ports": "false"}, false},
		{"true (insecure)", map[string]string{"runtime.enable-unprivileged-ports": "true"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestContainerdUnprivilegedICMP(t *testing.T) {
	rule := ruleContainerdUnprivilegedICMP
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (safe default)", map[string]string{}, false},
		{"false (secure)", map[string]string{"runtime.enable-unprivileged-icmp": "false"}, false},
		{"true (insecure)", map[string]string{"runtime.enable-unprivileged-icmp": "true"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestContainerdSnapshotter(t *testing.T) {
	rule := ruleContainerdSnapshotter
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (ok)", map[string]string{}, false},
		{"overlayfs (ok)", map[string]string{"runtime.snapshotter": "overlayfs"}, false},
		{"native (ok)", map[string]string{"runtime.snapshotter": "native"}, false},
		{"devmapper (warn)", map[string]string{"runtime.snapshotter": "devmapper"}, true},
		{"fuse-overlayfs (warn)", map[string]string{"runtime.snapshotter": "fuse-overlayfs"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestContainerdInsecureRegistryMirrors(t *testing.T) {
	rule := ruleContainerdInsecureRegistryMirrors
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"no mirrors", map[string]string{}, false},
		{"secure only", map[string]string{"runtime.registry-mirrors": "https://mirror.example.com"}, false},
		{"insecure mirror", map[string]string{"runtime.insecure-registry-mirrors": "http://insecure.example.com"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestContainerdRestrictOCIAnnotations(t *testing.T) {
	rule := ruleContainerdRestrictOCIAnnotations
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent", map[string]string{}, true},
		{"false", map[string]string{"runtime.restrict-oci-annotations": "false"}, true},
		{"true (secure)", map[string]string{"runtime.restrict-oci-annotations": "true"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}

func TestContainerdSeccompProfile(t *testing.T) {
	rule := ruleContainerdSeccompProfile
	tests := []struct {
		name    string
		values  map[string]string
		wantHit bool
	}{
		{"absent (ok - no explicit override)", map[string]string{}, false},
		{"unconfined (error)", map[string]string{"runtime.seccomp-profile": "unconfined"}, true},
		{"custom profile (ok)", map[string]string{"runtime.seccomp-profile": "/etc/seccomp/runtime.json"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rule.Check(tt.values)
			if tt.wantHit && f == nil {
				t.Error("expected finding, got nil")
			}
			if !tt.wantHit && f != nil {
				t.Errorf("unexpected finding: %s", f.Message)
			}
		})
	}
}
