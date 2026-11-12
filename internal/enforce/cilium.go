package enforce

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	policyv1alpha1 "github.com/armadasystems/policy-management/api/v1alpha1"
)

const fieldOwner = client.FieldOwner("policy-management")

var cnpGVK = schema.GroupVersionKind{Group: "cilium.io", Version: "v2", Kind: "CiliumNetworkPolicy"}

// BridgeBackend enforces AccessPolicy on a Bridge Kubernetes cluster:
// orchestrator LB for the ingress "public door", Cilium NetworkPolicies for the
// egress control and the ingress inner lock.
type BridgeBackend struct {
	K8s client.Client
	LB  OrchestratorLB
	// Namespace the model pods (and the generated CiliumNetworkPolicies) live in.
	Namespace string
	// GatewayNamespace is the only source allowed to reach the pods when blocked.
	GatewayNamespace string
}

func (b *BridgeBackend) EnsureIngressOpen(ctx context.Context, ap *policyv1alpha1.AccessPolicy) (string, error) {
	ip, err := b.LB.ProvisionEndpointLB(ctx, ap.Spec.EndpointRef.TenantID, ap.Spec.EndpointRef.ClusterID,
		ap.Spec.EndpointRef.EndpointID, ap.Spec.EndpointRef.Hostname, ap.Spec.Ingress.EnableExternalIP)
	if err != nil {
		return "", err
	}
	// Inner lock relaxed: allow in-cluster + gateway (the public door is the LB).
	if err := b.apply(ctx, b.ingressPolicy(ap, false)); err != nil {
		return ip, err
	}
	return ip, nil
}

func (b *BridgeBackend) EnsureIngressBlocked(ctx context.Context, ap *policyv1alpha1.AccessPolicy) error {
	// Authoritative: tear the public door down.
	if err := b.LB.DeprovisionEndpointLB(ctx, ap.Spec.EndpointRef.TenantID,
		ap.Spec.EndpointRef.ClusterID, ap.Spec.EndpointRef.EndpointID); err != nil {
		return err
	}
	// Inner lock: pods accept only the gateway namespace, nothing from the world.
	return b.apply(ctx, b.ingressPolicy(ap, true))
}

func (b *BridgeBackend) EnsureEgress(ctx context.Context, ap *policyv1alpha1.AccessPolicy) error {
	return b.apply(ctx, b.egressPolicy(ap))
}

// apply does a server-side apply of an unstructured CiliumNetworkPolicy.
func (b *BridgeBackend) apply(ctx context.Context, obj *unstructured.Unstructured) error {
	if err := b.K8s.Patch(ctx, obj, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply %s/%s: %w", obj.GetKind(), obj.GetName(), err)
	}
	return nil
}

func (b *BridgeBackend) base(name string, ap *policyv1alpha1.AccessPolicy) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(cnpGVK)
	u.SetNamespace(b.Namespace)
	u.SetName(name)
	u.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "policy-management", "policy.bridge.armada.ai/for": ap.Name})
	return u
}

// endpointSelector maps the spec PodSelector to a Cilium endpointSelector.
func endpointSelector(ap *policyv1alpha1.AccessPolicy) map[string]interface{} {
	return map[string]interface{}{"matchLabels": toIface(ap.Spec.PodSelector.MatchLabels)}
}

// egressPolicy: ALLOW = open; DENY = default-deny + DNS + cluster/private + toFQDNs allowlist.
func (b *BridgeBackend) egressPolicy(ap *policyv1alpha1.AccessPolicy) *unstructured.Unstructured {
	u := b.base("ap-"+ap.Name+"-egress", ap)

	var egress []interface{}
	// Always allow DNS to kube-dns (needed for toFQDNs and normal operation).
	egress = append(egress, map[string]interface{}{
		"toEndpoints": []interface{}{map[string]interface{}{
			"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s-app": "kube-dns"},
		}},
		"toPorts": []interface{}{map[string]interface{}{
			"ports": []interface{}{map[string]interface{}{"port": "53", "protocol": "ANY"}},
			"rules": map[string]interface{}{"dns": []interface{}{map[string]interface{}{"matchPattern": "*"}}},
		}},
	})
	// Always allow the in-cluster world and private networks.
	egress = append(egress, map[string]interface{}{"toEntities": []interface{}{"cluster", "host", "remote-node"}})
	egress = append(egress, map[string]interface{}{"toCIDRSet": []interface{}{
		map[string]interface{}{"cidr": "10.0.0.0/8"},
		map[string]interface{}{"cidr": "172.16.0.0/12"},
		map[string]interface{}{"cidr": "192.168.0.0/16"},
	}})

	if ap.Spec.Egress.DefaultAction == policyv1alpha1.Allow {
		egress = append(egress, map[string]interface{}{"toEntities": []interface{}{"world"}})
	} else if len(ap.Spec.Egress.AllowedFQDNs) > 0 {
		var fqdns []interface{}
		for _, d := range ap.Spec.Egress.AllowedFQDNs {
			fqdns = append(fqdns, map[string]interface{}{"matchName": d})
		}
		egress = append(egress, map[string]interface{}{"toFQDNs": fqdns})
	}

	_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{
		"endpointSelector": endpointSelector(ap),
		"egress":           sliceToIface(egress),
	}, "spec")
	return u
}

// ingressPolicy: when blocked, accept only the gateway namespace (world dropped);
// when open, additionally accept the cluster (the LB is the public door).
func (b *BridgeBackend) ingressPolicy(ap *policyv1alpha1.AccessPolicy, blocked bool) *unstructured.Unstructured {
	u := b.base("ap-"+ap.Name+"-ingress", ap)

	fromGateway := map[string]interface{}{
		"fromEndpoints": []interface{}{map[string]interface{}{
			"matchLabels": map[string]interface{}{"k8s:io.kubernetes.pod.namespace": b.GatewayNamespace},
		}},
	}
	ingress := []interface{}{fromGateway}
	if !blocked {
		ingress = append(ingress, map[string]interface{}{"fromEntities": []interface{}{"cluster"}})
	}

	_ = unstructured.SetNestedMap(u.Object, map[string]interface{}{
		"endpointSelector": endpointSelector(ap),
		"ingress":          ingress,
	}, "spec")
	return u
}

func toIface(m map[string]string) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sliceToIface(s []interface{}) []interface{} { return s }
