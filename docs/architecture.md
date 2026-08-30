# How everything fits together

A conceptual map of the lab. No commands here — just the mental model. For
manifests and exact paths, follow the inline links.

---

## The cast of components

Four layers, each with a clear job and a clear handoff to the next.

| Layer | Component(s) | Job |
|---|---|---|
| **Identity** | SPIRE server, SPIRE agent, spire-controller-manager, SPIFFE CSI driver | Issue SVIDs to workloads. Decide *which* workloads get *which* SPIFFE ID. |
| **Mesh** | istiod, istio-proxy sidecars (Envoy) | Carry traffic. Terminate and re-originate mTLS. Apply policy. |
| **Detection** | Tetragon, TracingPolicy | Watch syscalls in the kernel via eBPF. Match disallowed behavior. |
| **Revocation** | Translator, Actuator, the revoked-set | Translate a detection into a *deny* that the mesh enforces. |

The thesis measures how fast and how deterministically the **detection → revocation** loop closes; the identity and mesh layers exist to give the verdict a clean place to land.

---

## How a SPIFFE identity gets onto a workload

```
SPIRE Helm chart installs:
  • spire-server (issues certs)
  • spire-agent (runs per node, exposes Workload API socket via the SPIFFE CSI driver)
  • spire-controller-manager (sidecar in spire-server-0; watches ClusterSPIFFEID CRDs)

ClusterSPIFFEID "spire-controller-manager-service-account-based" (installed by chart):
  template = spiffe://{TrustDomain}/ns/{Namespace}/sa/{ServiceAccountName}
  podSelector = none, so it matches every pod in the cluster

A pod boots
  → controller-manager sees it
    → registers an entry in spire-server
      → spire-agent on that node mints an X.509-SVID
        → CSI driver mounts the agent socket into the pod
          → whoever inside the pod calls the Workload API gets the SVID
```

**The "whoever inside the pod" is `istio-proxy`, not the app** — the app
never sees the socket and links no SPIRE library.

The chart's object carries no `podSelector`, so the
`spiffe.io/spire-managed-identity: "true"` label on Service A/B doesn't
scope issuance — it's just the hook the actuator strips
([`docs/trial-reset.md`](trial-reset.md)).

Naming is locked to `spiffe://example.org/ns/<ns>/sa/<sa>` — service-account
is the stable selector since pod names churn. The translator reuses this
template to *construct* SPIFFE IDs from Tetragon event fields, no SPIRE API
lookup.

---

## How Istio consumes those identities

Vanilla Istio uses istiod's built-in Citadel CA. The integration
([`deploy/istio/istio-operator.yaml`](../deploy/istio/istio-operator.yaml))
swaps that out two ways:

1. **Trust domain alignment.** Istio defaults to `cluster.local`; SPIRE uses
   `example.org`. The overlay sets `meshConfig.trustDomain: example.org` so
   SVID SAN URIs match what Istio expects on the wire.
2. **A custom sidecar-injection template named `spire`.** Pods opt in via
   `inject.istio.io/templates: "sidecar,spire"`. It mounts the SPIFFE CSI
   volume into `istio-proxy` at `/run/secrets/workload-spiffe-uds` and sets
   `WORKLOAD_IDENTITY_SOCKET_FILE=spire-agent.sock` so the proxy looks for
   the socket SPIRE actually publishes, instead of the default name `socket`.

On startup the proxy logs:

```
Existing workload SDS socket found at var/run/secrets/workload-spiffe-uds/spire-agent.sock.
Default Istio SDS Server will only serve files
```

That's the one-line proof Envoy is reading certs from SPIRE rather than
istiod. The cert chain shows it too: issuer is `O=Example, CN=example.org`
(SPIRE's CA), not `O=cluster.local` (istiod).

---

## How A actually talks to B

```
service-a app          (plaintext HTTP localhost)
   │
   ▼
service-a istio-proxy  (holds SVID spiffe://example.org/ns/zta-ssf/sa/service-a)
   │
   │  mTLS over network
   │  presents SVID-A, verifies SVID-B against SPIRE trust bundle
   ▼
service-b istio-proxy  (holds SVID spiffe://example.org/ns/zta-ssf/sa/service-b)
   │
   ▼
service-b app          (plaintext HTTP localhost)
```

Both apps are unaware of TLS — they `http.Get`/`http.ListenAndServe`
plaintext on `:8080`; the mesh does the identity work. Enforcement sits in
the sidecar, not the application: deny logic inside Service B itself would
live in the workload being compromised, and measure a bespoke check instead
of the mesh's own.

---

## How revocation works

The detection side is a pure sensor — Tetragon emits, it does not act:

```
Compromise signal fires inside Service A (exec / egress / token-read)
  → Tetragon TracingPolicy matches (emit-only; no in-kernel response action)
     → event streams to the translator
        → translator resolves the SPIFFE ID (deterministic string mapping)
          and emits a CAEP-conformant SET with it as the subject
           → actuator receives the CAEP event
              → (parallel) remove the spiffe.io/spire-managed-identity pod label
              → (parallel) patch the deny into an Istio AuthorizationPolicy
                 → Service B's istio-proxy rejects Service A on subsequent calls
```

Envoy re-evaluates RBAC per request, so the deny lands on warm, pooled
connections too and carries no steady-state overhead. The measurement is
"time from policy match to the verdict being live at Service B" — ~147 ms
median across 300 trials ([Results (TL;DR)](../README.md#results-tldr)).

In parallel the actuator **strips the `spiffe.io/spire-managed-identity`
label** from A's pods. Not the real-time mechanism (an issued SVID stays
valid for its TTL) — it cuts off reissuance to other replicas and future
pods, though this cutoff is currently inert
([`docs/trial-reset.md`](trial-reset.md)).

---

## Why the layers are arranged this way

Non-obvious choices worth knowing before measuring:

- **SPIFFE ID resolution is deterministic string concatenation, not a SPIRE
  API call** — removing a network hop and a source of variance from
  measured latency.

- **Detection is the verdict** — the TracingPolicy's match condition *is*
  the decision; the actuator just actuates, keeping trials comparable.

- **Tetragon is emit-only; revocation is per-identity**, not per-process —
  it stops other replicas and future pods too (Envoy evaluates the deny
  per-request, covering warm connections). SIGKILL is out of scope: connect
  events attribute to Envoy, and killing A's loop would contaminate the
  latency measurement.

- **Trust domain is `example.org`** — the SPIRE Helm-chart default; what
  matters is that SPIRE and Istio agree, not which domain.

- **Native sidecars (Istio 1.23+) put `istio-proxy` in `initContainers[]`**,
  not `containers[]` — the SPIRE template targets it accordingly, and
  `kubectl get pod -o jsonpath='{.spec.containers[*].name}'` won't show the
  proxy. Use `READY: 2/2` instead.

---
