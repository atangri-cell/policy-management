package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	policyv1alpha1 "github.com/armadasystems/policy-management/api/v1alpha1"
	"github.com/armadasystems/policy-management/internal/enforce"
	"github.com/armadasystems/policy-management/internal/verify"
)

// AccessPolicyReconciler reconciles an AccessPolicy to the cluster's real state.
type AccessPolicyReconciler struct {
	client.Client
	Backend enforce.Backend
	Prober  *verify.Prober
	// RequeueInterval re-checks each policy periodically so drift is healed.
	RequeueInterval time.Duration
}

// +kubebuilder:rbac:groups=policy.bridge.armada.ai,resources=accesspolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy.bridge.armada.ai,resources=accesspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumnetworkpolicies,verbs=get;list;watch;create;update;patch;delete

func (r *AccessPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	lg := log.FromContext(ctx)

	var ap policyv1alpha1.AccessPolicy
	if err := r.Get(ctx, req.NamespacedName, &ap); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	desiredOpen := ap.Spec.Ingress.PublicEndpoints == policyv1alpha1.Allow && ap.Spec.Ingress.EndpointRequested

	// ---- Egress: apply the Cilium policy for the pods. ----
	ap.Status.Egress.Configured = ap.Spec.Egress.DefaultAction
	if err := r.Backend.EnsureEgress(ctx, &ap); err != nil {
		apimeta.SetStatusCondition(&ap.Status.Conditions,
			enforce.NewCondition(enforce.CondEgressReady, enforce.ReasonApplyFailed, err.Error(), false, ap.Generation))
		ap.Status.Egress.Consistent = false
		ap.Status.Egress.LastResult = "apply failed: " + err.Error()
		return r.finish(ctx, &ap, err)
	}
	ap.Status.Egress.Consistent = true
	ap.Status.Egress.LastResult = fmt.Sprintf("cilium egress applied (default=%s, %d allowed FQDNs)",
		ap.Spec.Egress.DefaultAction, len(ap.Spec.Egress.AllowedFQDNs))
	apimeta.SetStatusCondition(&ap.Status.Conditions,
		enforce.NewCondition(enforce.CondEgressReady, enforce.ReasonEnforced, ap.Status.Egress.LastResult, true, ap.Generation))

	// ---- Ingress: drive the public door to match the policy. ----
	ap.Status.Ingress.Configured = ap.Spec.Ingress.PublicEndpoints
	ap.Status.Ingress.DesiredReachable = desiredOpen

	var ip string
	var err error
	if desiredOpen {
		ip, err = r.Backend.EnsureIngressOpen(ctx, &ap)
	} else {
		err = r.Backend.EnsureIngressBlocked(ctx, &ap)
	}
	if err != nil {
		var refused *enforce.RefusedError
		reason := enforce.ReasonApplyFailed
		if errors.As(err, &refused) {
			reason = enforce.ReasonRefused // judged + rejected: a human must change something
		}
		apimeta.SetStatusCondition(&ap.Status.Conditions,
			enforce.NewCondition(enforce.CondIngressReady, reason, err.Error(), false, ap.Generation))
		ap.Status.Ingress.Consistent = false
		ap.Status.Ingress.LastResult = "apply failed: " + err.Error()
		// A refused request should not hot-loop; a transient fault retries sooner.
		if errors.As(err, &refused) {
			return r.finish(ctx, &ap, nil)
		}
		return r.finish(ctx, &ap, err)
	}
	if ip != "" {
		ap.Status.Ingress.EndpointIP = ip
	}

	// ---- Verify from outside: never report an unenforced DENY as success. ----
	verifyOn := ap.Spec.Verification == nil || ap.Spec.Verification.Enabled
	if !verifyOn || ap.Spec.EndpointRef.Hostname == "" {
		ap.Status.Ingress.Consistent = true
		ap.Status.Ingress.LastResult = fmt.Sprintf("enforced (open=%v); external verification skipped", desiredOpen)
		apimeta.SetStatusCondition(&ap.Status.Conditions,
			enforce.NewCondition(enforce.CondIngressReady, enforce.ReasonEnforced, ap.Status.Ingress.LastResult, true, ap.Generation))
		return r.finish(ctx, &ap, nil)
	}

	path, timeout, insecure := "/", 10*time.Second, true
	if v := ap.Spec.Verification; v != nil {
		if v.Path != "" {
			path = v.Path
		}
		if v.TimeoutSeconds > 0 {
			timeout = time.Duration(v.TimeoutSeconds) * time.Second
		}
		insecure = v.InsecureTLS
	}
	_ = insecure // prober is constructed with the insecure setting at startup
	res := r.Prober.Probe(ctx, ap.Spec.EndpointRef.Hostname, path, timeout)
	now := metav1.Now()
	ap.Status.LastVerifiedTime = &now
	ap.Status.Ingress.EffectiveReachable = &res.Reachable
	ap.Status.Ingress.Consistent = res.Reachable == desiredOpen

	if ap.Status.Ingress.Consistent {
		ap.Status.Ingress.LastResult = fmt.Sprintf("ENFORCED open=%v, externally verified (HTTP %d) in %s",
			desiredOpen, res.Code, res.Latency.Round(time.Millisecond))
		apimeta.SetStatusCondition(&ap.Status.Conditions,
			enforce.NewCondition(enforce.CondIngressReady, enforce.ReasonEnforced, ap.Status.Ingress.LastResult, true, ap.Generation))
		return r.finish(ctx, &ap, nil)
	}

	// The critical case: desired blocked but still reachable (or vice-versa).
	ap.Status.Ingress.LastResult = fmt.Sprintf(
		"ENFORCEMENT ERROR: desired open=%v but external probe shows reachable=%v (HTTP %d)",
		desiredOpen, res.Reachable, res.Code)
	lg.Error(nil, ap.Status.Ingress.LastResult, "accesspolicy", ap.Name)
	apimeta.SetStatusCondition(&ap.Status.Conditions,
		enforce.NewCondition(enforce.CondIngressReady, enforce.ReasonEnforcementError, ap.Status.Ingress.LastResult, false, ap.Generation))
	// Requeue soon to re-check (NAT/LB propagation) — but it is NOT reported as success.
	if err := r.updateStatus(ctx, &ap); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

// finish writes status and schedules the next drift-reconcile.
func (r *AccessPolicyReconciler) finish(ctx context.Context, ap *policyv1alpha1.AccessPolicy, err error) (ctrl.Result, error) {
	ap.Status.ObservedGeneration = ap.Generation
	if uerr := r.updateStatus(ctx, ap); uerr != nil {
		return ctrl.Result{}, uerr
	}
	if err != nil {
		return ctrl.Result{}, err // controller-runtime backs off and retries
	}
	interval := r.RequeueInterval
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

func (r *AccessPolicyReconciler) updateStatus(ctx context.Context, ap *policyv1alpha1.AccessPolicy) error {
	if err := r.Status().Update(ctx, ap); err != nil && !apierrors.IsConflict(err) {
		return err
	}
	return nil
}

func (r *AccessPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&policyv1alpha1.AccessPolicy{}).
		Complete(r)
}
