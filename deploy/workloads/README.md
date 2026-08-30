# deploy/workloads

Kubernetes manifests for the four lab workloads.

| File              | Notes |
|-------------------|-------|
| `namespace.yaml`  | `zta-ssf` namespace. Carries the `istio.io/rev=default` label so the sidecar injector webhook matches. |
| `service-a.yaml`  | Dummy caller. Plaintext HTTP to its sidecar; sidecar holds the SPIRE-issued SVID and does mTLS to B. |
| `service-b.yaml`  | Dummy callee + enforcement point. Plaintext HTTP listener on `:8080`; sidecar terminates mTLS. |
| `translator.yaml` | Tetragon stream consumer; dials the agent's gRPC service and POSTs SETs to the actuator. |
| `actuator.yaml`  | CAEP consumer + mesh actuation via `AuthorizationPolicy` patch (docs/architecture.md). No SPIRE socket mount needed — it's a Kubernetes-only client. |
| `service-a-trial.yaml` | **Trial harness.** Busybox-variant of A carrying A's identity but a shell — the attacker's vehicle for triggering the three scenarios. Idle by design (the Go `/app` stays the B-prober). |
| `c2-sink.yaml`    | **Trial harness.** Plain TCP listener on `:9666` (sidecar injection off) — the C2 callback target for the egress scenario. Port must match `../tetragon/tracingpolicy-egress.yaml`. |

Apply order:

```sh
kubectl apply -f namespace.yaml
make workloads-apply
```

SPIRE registration entries are **not** in this directory — they're minted
automatically from a selector-less `ClusterSPIFFEID`, which is why the
`spiffe.io/spire-managed-identity: "true"` label on Service A/B is currently
just a hook (docs/trial-reset.md). Identity wiring lives in
[`../istio/istio-operator.yaml`](../istio/istio-operator.yaml); full picture
in [`docs/architecture.md`](../../docs/architecture.md).
