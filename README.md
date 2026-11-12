# policy-management

GPU network **access-control operator** for Bridge Kubernetes clusters. A single
declarative `AccessPolicy` custom resource governs, per model endpoint, whether it
is reachable from the internet (**ingress**) and whether its pods can reach the
internet (**egress**) — reconciled continuously and **verified from a real
external client**, so an unenforced `DENY` is never reported as success.

> **Not the Azure PoC.** An earlier PoC enforced public-endpoint ALLOW/DENY with
> an Azure **NSG** rule on a VM NIC. That mechanism does **not** exist on a
> Kubernetes cluster and is deliberately **not** carried over. Only the *idea*
> survives — a declarative policy, a reconcile loop, and external verification.
> The enforcement here is entirely Kubernetes-native.

## How enforcement works on K8s

| Direction | What "the door" is | ALLOW | DENY |
|---|---|---|---|
| **Ingress** | the endpoint LoadBalancer (MetalLB VIP) + gateway in front | provision the LB via the orchestrator | **deprovision** the LB + Cilium ingress policy that drops the world |
| **Egress** | a Cilium policy on the model pods | allow `world` | default-deny + `toFQDNs` allowlist (DNS + private always allowed) |

- **Ingress** is driven through the Bridge **orchestrator** (`ProvisionEndpointLB` /
  `DeprovisionEndpointLB`) — the authoritative "public door" — with a Cilium
  **ingress** `CiliumNetworkPolicy` as an inner lock so pods only accept the gateway.
- **Egress** is a Cilium **egress** `CiliumNetworkPolicy` on the selected pods
  (the same layer Manas's PoC used), evolved from binary on/off to **default-deny +
  FQDN allowlist**.
- **Verification**: after each change the controller probes the endpoint's public
  hostname from outside. `effectiveReachable != desiredReachable` → status condition
  `EnforcementError`, requeue — **never** reported as success. ("The orchestrator
  provisioned a VIP" ≠ "it is reachable" — NAT and the gateway sit in front.)
- **Drift**: the operator re-reconciles on an interval, so a door that drifts open
  (or shut) is healed, not just set once.

## The API

```yaml
apiVersion: policy.bridge.armada.ai/v1alpha1
kind: AccessPolicy
spec:
  endpointRef: { tenantID, clusterID, endpointID, hostname }   # the Bridge token-factory endpoint
  podSelector: { matchLabels: {...} }                          # the model pods
  ingress: { publicEndpoints: ALLOW|DENY, endpointRequested: bool, enableExternalIP: bool }
  egress:  { defaultAction: ALLOW|DENY, allowedFQDNs: [...] }
  verification: { enabled: true, path: /v1/models, timeoutSeconds: 10, insecureTLS: true }
status:
  ingress: { configured, desiredReachable, effectiveReachable, endpointIP, consistent, lastResult }
  egress:  { configured, consistent, lastResult }
  conditions: [ IngressEnforced, EgressEnforced ]
```

Effective ingress reachability = `publicEndpoints == ALLOW AND endpointRequested`.

See [`config/samples/accesspolicy_coding_pilot.yaml`](config/samples/accesspolicy_coding_pilot.yaml)
for the coding-pilot endpoint.

## Layout

```
api/v1alpha1/            AccessPolicy CRD types (+ scaffold deepcopy)
internal/controller/     reconcile loop: enforce -> verify -> status/conditions
internal/enforce/        pluggable Backend:
                           backend.go       interface + orchestrator contract
                           orchestrator.go  HTTP client for Provision/DeprovisionEndpointLB
                           cilium.go        BridgeBackend: Cilium ingress/egress policies
internal/verify/         external reachability prober
cmd/main.go              manager wiring
config/crd, config/samples
```

## Quickstart

```bash
make tidy generate manifests     # fill deps, regenerate deepcopy + CRD from markers
make install                     # apply the CRD
ORCHESTRATOR_URL=http://bridge-orchestrator:8080 \
MODEL_NAMESPACE=armada-system GATEWAY_NAMESPACE=envoy-gateway-system \
  make run                       # run the controller against your kubeconfig
make sample                      # apply the example AccessPolicy
kubectl get accesspolicy -n armada-system -o wide
```

## Scaffold status — what's real vs. TODO

This is a working skeleton that captures the design; before production:

- **Orchestrator auth** — `internal/enforce/orchestrator.go` has no identity wiring
  yet (`AuthHeader` is a placeholder). Attach the real service-account/session.
- **DeepCopy & CRD** — `zz_generated.deepcopy.go` and the CRD YAML are hand-written
  scaffolds; run `make generate manifests` (controller-gen) for the authoritative versions.
- **Egress verification** — ingress is externally probed; egress ("is the internet
  really blocked?") should also be confirmed via an in-pod exec probe (TODO).
- **Edge backend** — on Galleon/Leviathan a "public endpoint" is a managed
  tunnel/relay, not a LoadBalancer; add an `EdgeBackend` implementing the same
  `enforce.Backend` interface (tunnel teardown) — the controller/verifier are reused.
- **Cilium CRD** — assumes `CiliumNetworkPolicy` (cilium.io/v2) is installed on the cluster.
```
