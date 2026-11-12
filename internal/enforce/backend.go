// Package enforce holds the pluggable enforcement backends for AccessPolicy.
//
// The Azure NSG approach from the earlier PoC does NOT apply on Kubernetes and is
// deliberately not ported. On a Bridge K8s cluster:
//
//   - Ingress is enforced by provisioning/deprovisioning the endpoint LoadBalancer
//     through the Bridge orchestrator (the authoritative "public door"), plus a
//     Cilium ingress NetworkPolicy on the pods as an inner lock.
//   - Egress is enforced by a Cilium egress NetworkPolicy on the model pods.
//
// The controller and the external verifier are backend-agnostic; only the
// enforcement calls below change per platform.
package enforce

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	policyv1alpha1 "github.com/armadasystems/policy-management/api/v1alpha1"
)

// Backend applies the desired access posture to the underlying cluster.
type Backend interface {
	// EnsureIngressOpen provisions the endpoint LoadBalancer (public door) and
	// allows the gateway to reach the pods. Returns the endpoint IP, if known.
	EnsureIngressOpen(ctx context.Context, ap *policyv1alpha1.AccessPolicy) (ip string, err error)

	// EnsureIngressBlocked deprovisions the endpoint LoadBalancer and applies a
	// Cilium ingress policy that drops all non-gateway inbound traffic.
	EnsureIngressBlocked(ctx context.Context, ap *policyv1alpha1.AccessPolicy) error

	// EnsureEgress applies the Cilium egress NetworkPolicy for the pods per spec
	// (ALLOW = open; DENY = default-deny + the toFQDNs allowlist, DNS and private
	// networks always permitted).
	EnsureEgress(ctx context.Context, ap *policyv1alpha1.AccessPolicy) error
}

// OrchestratorLB is the subset of the Bridge orchestrator API the ingress backend
// uses. It mirrors platform-manager's own client contract so the two stay aligned.
type OrchestratorLB interface {
	ProvisionEndpointLB(ctx context.Context, tenantID, clusterID, endpointID, hostname string, enableExternalIP bool) (ip string, err error)
	DeprovisionEndpointLB(ctx context.Context, tenantID, clusterID, endpointID string) error
}

// RefusedError marks a 4xx from the orchestrator: the request was judged and
// rejected (a human must change something), so the controller should not retry
// it as if it were a transient fault.
type RefusedError struct {
	StatusCode int
	Message    string
}

func (e *RefusedError) Error() string { return e.Message }

// Condition type/reasons surfaced on AccessPolicy.status.conditions.
const (
	CondIngressReady = "IngressEnforced"
	CondEgressReady  = "EgressEnforced"

	ReasonEnforced         = "Enforced"
	ReasonEnforcementError = "EnforcementError"
	ReasonApplyFailed      = "ApplyFailed"
	ReasonRefused          = "Refused"
)

// NewCondition is a small helper for status conditions.
func NewCondition(condType, reason, msg string, ok bool, gen int64) metav1.Condition {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	return metav1.Condition{
		Type:               condType,
		Status:             st,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: gen,
		LastTransitionTime: metav1.Now(),
	}
}
