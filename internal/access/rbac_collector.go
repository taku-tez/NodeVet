package access

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// RBACCollector fetches RBAC objects from the cluster.
type RBACCollector struct {
	KubeconfigPath string
	Context        string
}

func buildClientset(kubeconfigPath, kubeContext string) (*kubernetes.Clientset, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		loadingRules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	if kubeContext != "" {
		overrides.CurrentContext = kubeContext
	}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules, overrides,
	).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("building kubeconfig: %w", err)
	}
	return kubernetes.NewForConfig(cfg)
}

// CollectRBACRisks scans ClusterRoles, Roles, and their bindings for dangerous permissions.
// Returns (nodeProxyBindings, podExecBindings, error).
// podExecBindings includes both cluster-scoped ClusterRoleBindings and namespace-scoped RoleBindings.
func (c *RBACCollector) CollectRBACRisks(ctx context.Context) ([]RBACBinding, []RBACBinding, error) {
	cs, err := buildClientset(c.KubeconfigPath, c.Context)
	if err != nil {
		return nil, nil, err
	}

	// --- ClusterRoles ---
	crList, err := cs.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("listing ClusterRoles: %w", err)
	}

	nodeProxyRoles := map[string][]string{} // clusterRoleName → verbs
	podExecRoles := map[string][]string{}   // clusterRoleName → verbs

	for _, cr := range crList.Items {
		for _, rule := range cr.Rules {
			if ruleGrantsNodeProxy(rule) {
				nodeProxyRoles[cr.Name] = rule.Verbs
			}
			if ruleGrantsPodExec(rule) {
				podExecRoles[cr.Name] = rule.Verbs
			}
		}
	}

	// --- Namespace-scoped Roles ---
	// key: "namespace/roleName" → verbs
	namespacedPodExecRoles := map[string][]string{}
	roleList, err := cs.RbacV1().Roles("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("listing Roles: %w", err)
	}
	for _, r := range roleList.Items {
		for _, rule := range r.Rules {
			if ruleGrantsPodExec(rule) {
				key := r.Namespace + "/" + r.Name
				namespacedPodExecRoles[key] = rule.Verbs
			}
		}
	}

	var nodeProxyBindings, podExecBindings []RBACBinding

	// --- ClusterRoleBindings (cluster-scoped) ---
	crbList, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("listing ClusterRoleBindings: %w", err)
	}
	for _, crb := range crbList.Items {
		roleName := crb.RoleRef.Name
		subjects := convertSubjects(crb.Subjects)
		if verbs, ok := nodeProxyRoles[roleName]; ok {
			nodeProxyBindings = append(nodeProxyBindings, RBACBinding{
				RoleKind:  "ClusterRole",
				RoleName:  roleName,
				Namespace: "",
				Verbs:     verbs,
				Resources: []string{"nodes/proxy"},
				Subjects:  subjects,
			})
		}
		if verbs, ok := podExecRoles[roleName]; ok {
			podExecBindings = append(podExecBindings, RBACBinding{
				RoleKind:  "ClusterRole",
				RoleName:  roleName,
				Namespace: "",
				Verbs:     verbs,
				Resources: []string{"pods/exec", "pods/attach"},
				Subjects:  subjects,
			})
		}
	}

	// --- RoleBindings (namespace-scoped) ---
	// A RoleBinding may reference either a ClusterRole or a namespace Role.
	rbList, err := cs.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("listing RoleBindings: %w", err)
	}
	for _, rb := range rbList.Items {
		subjects := convertSubjects(rb.Subjects)
		switch rb.RoleRef.Kind {
		case "ClusterRole":
			// RoleBinding references a ClusterRole — scoped to rb.Namespace
			if verbs, ok := podExecRoles[rb.RoleRef.Name]; ok {
				podExecBindings = append(podExecBindings, RBACBinding{
					RoleKind:  "ClusterRole",
					RoleName:  rb.RoleRef.Name,
					Namespace: rb.Namespace,
					Verbs:     verbs,
					Resources: []string{"pods/exec", "pods/attach"},
					Subjects:  subjects,
				})
			}
		case "Role":
			key := rb.Namespace + "/" + rb.RoleRef.Name
			if verbs, ok := namespacedPodExecRoles[key]; ok {
				podExecBindings = append(podExecBindings, RBACBinding{
					RoleKind:  "Role",
					RoleName:  rb.RoleRef.Name,
					Namespace: rb.Namespace,
					Verbs:     verbs,
					Resources: []string{"pods/exec", "pods/attach"},
					Subjects:  subjects,
				})
			}
		}
	}

	return nodeProxyBindings, podExecBindings, nil
}

// ruleGrantsNodeProxy checks if a PolicyRule grants access to nodes/proxy.
func ruleGrantsNodeProxy(rule rbacv1.PolicyRule) bool {
	hasNodes := false
	for _, r := range rule.Resources {
		if r == "nodes/proxy" || r == "nodes/*" || r == "*" {
			hasNodes = true
			break
		}
	}
	if !hasNodes {
		return false
	}
	for _, v := range rule.Verbs {
		if v == "get" || v == "create" || v == "*" {
			return true
		}
	}
	return false
}

// ruleGrantsPodExec checks if a PolicyRule grants pods/exec or pods/attach.
func ruleGrantsPodExec(rule rbacv1.PolicyRule) bool {
	hasExec := false
	for _, r := range rule.Resources {
		if r == "pods/exec" || r == "pods/attach" || r == "pods/*" || r == "*" {
			hasExec = true
			break
		}
	}
	if !hasExec {
		return false
	}
	for _, v := range rule.Verbs {
		if v == "get" || v == "create" || v == "*" {
			return true
		}
	}
	return false
}

func convertSubjects(subjects []rbacv1.Subject) []Subject {
	result := make([]Subject, len(subjects))
	for i, s := range subjects {
		result[i] = Subject{
			Kind:      s.Kind,
			Name:      s.Name,
			Namespace: s.Namespace,
		}
	}
	return result
}

// FormatSubjects formats subjects as a readable string.
func FormatSubjects(subjects []Subject) string {
	parts := make([]string, len(subjects))
	for i, s := range subjects {
		switch s.Kind {
		case "ServiceAccount":
			parts[i] = fmt.Sprintf("SA:%s/%s", s.Namespace, s.Name)
		case "Group":
			parts[i] = fmt.Sprintf("Group:%s", s.Name)
		default:
			parts[i] = fmt.Sprintf("User:%s", s.Name)
		}
	}
	return strings.Join(parts, ", ")
}
