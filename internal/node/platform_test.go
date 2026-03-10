package node

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeNode(name string, labels, annotations map[string]string, conditions []corev1.NodeCondition) corev1.Node {
	return corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      labels,
			Annotations: annotations,
		},
		Status: corev1.NodeStatus{
			Conditions: conditions,
		},
	}
}

func TestDetectPlatformGKE(t *testing.T) {
	n := makeNode("gke-node", map[string]string{
		"cloud.google.com/gke-nodepool": "pool-1",
		"cloud.google.com/gke-shielded-integrity-monitoring": "true",
		"cloud.google.com/gke-secure-boot":                   "true",
		"iam.gke.io/gke-metadata-server-enabled":             "true",
	}, nil, nil)

	info := FromK8sNode(n)
	if info.Platform != PlatformGKE {
		t.Errorf("expected GKE, got %s", info.Platform)
	}
	if info.GKE == nil {
		t.Fatal("GKE info should not be nil")
	}
	if !info.GKE.IntegrityMonitoring {
		t.Error("IntegrityMonitoring should be true")
	}
	if !info.GKE.SecureBoot {
		t.Error("SecureBoot should be true")
	}
	if !info.GKE.WorkloadIdentityEnabled {
		t.Error("WorkloadIdentityEnabled should be true")
	}
}

func TestDetectPlatformEKS(t *testing.T) {
	n := makeNode("eks-node", map[string]string{
		"eks.amazonaws.com/nodegroup":     "my-ng",
		"eks.amazonaws.com/capacityType":  "ON_DEMAND",
		"eks.amazonaws.com/release-version": "1.29.3-20240501",
	}, nil, nil)

	info := FromK8sNode(n)
	if info.Platform != PlatformEKS {
		t.Errorf("expected EKS, got %s", info.Platform)
	}
	if info.EKS == nil {
		t.Fatal("EKS info should not be nil")
	}
	if info.EKS.NodeGroup != "my-ng" {
		t.Errorf("NodeGroup: got %s, want my-ng", info.EKS.NodeGroup)
	}
}

func TestDetectPlatformAKS(t *testing.T) {
	n := makeNode("aks-node", map[string]string{
		"kubernetes.azure.com/agentpool": "nodepool1",
		"kubernetes.azure.com/os-sku":    "Ubuntu",
	}, map[string]string{
		"kubernetes.azure.com/defender-profile":   "default",
		"kubernetes.azure.com/disk-encryption-set": "/subscriptions/.../des-1",
	}, nil)

	info := FromK8sNode(n)
	if info.Platform != PlatformAKS {
		t.Errorf("expected AKS, got %s", info.Platform)
	}
	if info.AKS == nil {
		t.Fatal("AKS info should not be nil")
	}
	if info.AKS.DefenderAnnotation != "default" {
		t.Errorf("DefenderAnnotation: got %s", info.AKS.DefenderAnnotation)
	}
}

func TestDetectPlatformUnknown(t *testing.T) {
	n := makeNode("plain-node", map[string]string{
		"kubernetes.io/hostname": "plain-node",
	}, nil, nil)

	info := FromK8sNode(n)
	if info.Platform != PlatformUnknown {
		t.Errorf("expected Unknown, got %s", info.Platform)
	}
}

func TestNodeConditions(t *testing.T) {
	n := makeNode("node1", nil, nil, []corev1.NodeCondition{
		{Type: "Ready", Status: corev1.ConditionTrue},
		{Type: "MemoryPressure", Status: corev1.ConditionFalse},
		{Type: "DiskPressure", Status: corev1.ConditionTrue},
	})

	info := FromK8sNode(n)
	if info.Condition("Ready") != ConditionTrue {
		t.Error("Ready should be True")
	}
	if info.Condition("MemoryPressure") != ConditionFalse {
		t.Error("MemoryPressure should be False")
	}
	if info.Condition("DiskPressure") != ConditionTrue {
		t.Error("DiskPressure should be True")
	}
	if info.Condition("Unknown") != ConditionUnknown {
		t.Error("absent condition should be Unknown")
	}
}
