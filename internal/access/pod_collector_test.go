package access

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func boolPtr(b bool) *bool { return &b }

func makePod(name, namespace string, spec corev1.PodSpec) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec:       spec,
	}
}

func TestAnalyzePod_HostPID(t *testing.T) {
	pod := makePod("test", "default", corev1.PodSpec{HostPID: true})
	risk := analyzePod(pod)
	if risk == nil {
		t.Fatal("expected risk, got nil")
	}
	if !risk.HostPID {
		t.Error("expected HostPID=true")
	}
}

func TestAnalyzePod_Privileged(t *testing.T) {
	pod := makePod("test", "default", corev1.PodSpec{
		Containers: []corev1.Container{
			{
				Name: "app",
				SecurityContext: &corev1.SecurityContext{
					Privileged: boolPtr(true),
				},
			},
		},
	})
	risk := analyzePod(pod)
	if risk == nil {
		t.Fatal("expected risk, got nil")
	}
	if !risk.Privileged {
		t.Error("expected Privileged=true")
	}
}

func TestAnalyzePod_SensitiveHostPath(t *testing.T) {
	pod := makePod("test", "default", corev1.PodSpec{
		Volumes: []corev1.Volume{
			{
				Name: "host-etc",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/etc"},
				},
			},
		},
	})
	risk := analyzePod(pod)
	if risk == nil {
		t.Fatal("expected risk for /etc hostPath")
	}
	if len(risk.HostPaths) == 0 {
		t.Error("expected HostPaths to contain /etc")
	}
}

func TestAnalyzePod_SafeHostPath(t *testing.T) {
	pod := makePod("test", "default", corev1.PodSpec{
		Volumes: []corev1.Volume{
			{
				Name: "logs",
				VolumeSource: corev1.VolumeSource{
					HostPath: &corev1.HostPathVolumeSource{Path: "/var/log/myapp"},
				},
			},
		},
	})
	risk := analyzePod(pod)
	if risk != nil {
		t.Errorf("expected no risk for /var/log/myapp, got: %+v", risk)
	}
}

func TestAnalyzePod_Clean(t *testing.T) {
	pod := makePod("clean", "default", corev1.PodSpec{
		Containers: []corev1.Container{{Name: "app"}},
	})
	risk := analyzePod(pod)
	if risk != nil {
		t.Errorf("expected no risk for clean pod, got: %+v", risk)
	}
}

func TestIsSensitiveHostPath(t *testing.T) {
	tests := []struct {
		path      string
		sensitive bool
	}{
		{"/etc", true},
		{"/etc/kubernetes", true},
		{"/var/run/docker.sock", true},
		{"/proc", true},
		{"/var/log/myapp", false},
		{"/data/app", false},
		{"/", true},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isSensitiveHostPath(tt.path)
			if got != tt.sensitive {
				t.Errorf("path %s: got %v, want %v", tt.path, got, tt.sensitive)
			}
		})
	}
}
