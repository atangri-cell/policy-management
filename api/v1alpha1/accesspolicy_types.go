package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AccessDecision is the ALLOW/DENY value of a policy direction.
// +kubebuilder:validation:Enum=ALLOW;DENY
type AccessDecision string

const (
	Allow AccessDecision = "ALLOW"
	Deny  AccessDecision = "DENY"
)

// EndpointRef identifies the Bridge Token-Factory endpoint this policy governs.
// These are the same identifiers the orchestrator LB API takes.
type EndpointRef struct {
	TenantID   string `json:"tenantID"`
	ClusterID  string `json:"clusterID"`
	EndpointID string `json:"endpointID"`
	// Hostname is the public hostname the external prober checks.
	Hostname string `json:"hostname"`
}

// IngressPolicy controls whether the endpoint is reachable from the public internet.
//
// Effective reachability = (PublicEndpoints == ALLOW) AND EndpointRequested.
// Enforced by provisioning/deprovisioning the endpoint LoadBalancer via the
// orchestrator, plus a Cilium ingress policy on the pods as an inner lock.
type IngressPolicy struct {
	// +kubebuilder:default=ALLOW
	PublicEndpoints AccessDecision `json:"publicEndpoints"`
	// EndpointRequested is whether a public endpoint is actually wanted.
	EndpointRequested bool `json:"endpointRequested"`
	// EnableExternalIP is passed through to the orchestrator LB provisioning.
	EnableExternalIP bool `json:"enableExternalIP,omitempty"`
}

// EgressPolicy controls the model pods' outbound internet access, enforced by a
// Cilium (egress) NetworkPolicy on the selected pods.
//
// Production posture is DefaultAction=DENY with an explicit AllowedFQDNs list
// (Cilium toFQDNs); in-cluster DNS and private networks are always permitted.
type EgressPolicy struct {
	// +kubebuilder:default=DENY
	DefaultAction AccessDecision `json:"defaultAction"`
	// AllowedFQDNs are the domains still permitted when DefaultAction=DENY.
	AllowedFQDNs []string `json:"allowedFQDNs,omitempty"`
}

// Verification configures the external reachability probe used to confirm
// enforcement before a direction is reported as successfully applied.
type Verification struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled"`
	// Path probed over HTTPS against EndpointRef.Hostname (default "/").
	Path string `json:"path,omitempty"`
	// +kubebuilder:default=10
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
	// InsecureTLS skips cert verification (Bridge endpoints are self-signed).
	InsecureTLS bool `json:"insecureTLS,omitempty"`
}

// AccessPolicySpec is the desired access posture for one endpoint + its pods.
type AccessPolicySpec struct {
	EndpointRef EndpointRef `json:"endpointRef"`
	// PodSelector selects the model pods the Cilium policies target.
	PodSelector  metav1.LabelSelector `json:"podSelector"`
	Ingress      IngressPolicy        `json:"ingress"`
	Egress       EgressPolicy         `json:"egress"`
	Verification *Verification        `json:"verification,omitempty"`
}

// DirectionStatus is the observed state of one direction (ingress or egress).
type DirectionStatus struct {
	Configured       AccessDecision `json:"configured,omitempty"`
	DesiredReachable bool           `json:"desiredReachable"`
	// EffectiveReachable is what the external probe actually observed (nil = not yet verified).
	EffectiveReachable *bool  `json:"effectiveReachable,omitempty"`
	EndpointIP         string `json:"endpointIP,omitempty"`
	// Consistent is true only when effective matches desired.
	Consistent bool   `json:"consistent"`
	LastResult string `json:"lastResult,omitempty"`
}

// AccessPolicyStatus is the observed state of the AccessPolicy.
type AccessPolicyStatus struct {
	ObservedGeneration int64              `json:"observedGeneration,omitempty"`
	Ingress            DirectionStatus    `json:"ingress,omitempty"`
	Egress             DirectionStatus    `json:"egress,omitempty"`
	LastVerifiedTime   *metav1.Time       `json:"lastVerifiedTime,omitempty"`
	Conditions         []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=accesspolicy;ap
// +kubebuilder:printcolumn:name="Ingress",type=string,JSONPath=`.spec.ingress.publicEndpoints`
// +kubebuilder:printcolumn:name="Egress",type=string,JSONPath=`.spec.egress.defaultAction`
// +kubebuilder:printcolumn:name="Reachable",type=boolean,JSONPath=`.status.ingress.effectiveReachable`
// +kubebuilder:printcolumn:name="Consistent",type=boolean,JSONPath=`.status.ingress.consistent`

// AccessPolicy is the Schema for the accesspolicies API.
type AccessPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AccessPolicySpec   `json:"spec,omitempty"`
	Status AccessPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AccessPolicyList contains a list of AccessPolicy.
type AccessPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AccessPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AccessPolicy{}, &AccessPolicyList{})
}
