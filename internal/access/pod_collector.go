package access

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CollectPodRisks scans all pods for dangerous security configurations.
func (c *RBACCollector) CollectPodRisks(ctx context.Context) ([]PodRisk, error) {
	cs, err := buildClientset(c.KubeconfigPath, c.Context)
	if err != nil {
		return nil, err
	}

	podList, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods: %w", err)
	}

	var risks []PodRisk
	for _, pod := range podList.Items {
		risk := analyzePod(pod)
		if risk != nil {
			risks = append(risks, *risk)
		}
	}
	return risks, nil
}

func analyzePod(pod corev1.Pod) *PodRisk {
	spec := pod.Spec
	risk := &PodRisk{
		Namespace:         pod.Namespace,
		PodName:           pod.Name,
		HostPID:           spec.HostPID,
		HostNetwork:       spec.HostNetwork,
		HostIPC:           spec.HostIPC,
		IsSystemNamespace: SystemNamespaces[pod.Namespace],
	}

	// Check containers for privileged mode
	for _, c := range append(spec.Containers, spec.InitContainers...) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			risk.Privileged = true
			risk.ContainerName = c.Name
			break
		}
	}

	// Check hostPath volumes for sensitive paths
	for _, vol := range spec.Volumes {
		if vol.HostPath != nil {
			path := vol.HostPath.Path
			if isSensitiveHostPath(path) {
				risk.HostPaths = append(risk.HostPaths, path)
			}
		}
	}

	if !risk.HostPID && !risk.HostNetwork && !risk.HostIPC && !risk.Privileged && len(risk.HostPaths) == 0 {
		return nil
	}
	return risk
}

func isSensitiveHostPath(path string) bool {
	for _, sensitive := range SensitiveHostPaths {
		if path == sensitive || strings.HasPrefix(path, sensitive+"/") {
			return true
		}
	}
	return false
}
