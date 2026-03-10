package source

import "testing"

func TestContainerdSourceSecure(t *testing.T) {
	src := NewContainerdSource("testdata/containerd-secure.toml")
	values, err := src.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	expect := map[string]string{
		"runtime.enable-unprivileged-ports": "false",
		"runtime.enable-unprivileged-icmp":  "false",
		"runtime.restrict-oci-annotations":  "true",
		"runtime.snapshotter":               "overlayfs",
		"runtime.registry-mirrors":          "https://mirror.example.com",
	}
	for k, wantV := range expect {
		if gotV, ok := values[k]; !ok {
			t.Errorf("missing key %q", k)
		} else if gotV != wantV {
			t.Errorf("key %q: got %q, want %q", k, gotV, wantV)
		}
	}
	if _, ok := values["runtime.insecure-registry-mirrors"]; ok {
		t.Error("should not have insecure registry mirrors")
	}
}

func TestContainerdSourceInsecure(t *testing.T) {
	src := NewContainerdSource("testdata/containerd-insecure.toml")
	values, err := src.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	expect := map[string]string{
		"runtime.enable-unprivileged-ports": "true",
		"runtime.enable-unprivileged-icmp":  "true",
		"runtime.restrict-oci-annotations":  "false",
		"runtime.snapshotter":               "devmapper",
	}
	for k, wantV := range expect {
		if gotV, ok := values[k]; !ok {
			t.Errorf("missing key %q", k)
		} else if gotV != wantV {
			t.Errorf("key %q: got %q, want %q", k, gotV, wantV)
		}
	}
	if v, ok := values["runtime.insecure-registry-mirrors"]; !ok || v == "" {
		t.Error("should have insecure registry mirrors")
	}
}

func TestParseContainerdConfigInvalid(t *testing.T) {
	_, err := ParseContainerdConfig([]byte("not valid toml [[["))
	if err == nil {
		t.Error("expected error for invalid TOML, got nil")
	}
}
