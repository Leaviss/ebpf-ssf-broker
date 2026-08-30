# Reproducing the tooling foundation

Step-by-step to stand up the lab from an empty single-node cluster to
"Service A talks to Service B over SPIRE-issued mTLS through Istio" — the
**foundation** that detection, the translator/actuator pipeline, and the
trial harness build on (README).

> **Fast path:** [`docs/demo.md`](demo.md) stands all of this up with one
> `make lab-up` (`scripts/lab-up.sh` runs §1–§5 plus detection and
> observability, same pins). This file is the fully annotated install record
> — come here when a step fails or you want to know why one exists.

> The versions pinned below are what this lab was built and measured on —
> record what you used if you deviate.

---

## 0. Prerequisites

OrbStack is the tested environment; any single-node Kubernetes cluster should
work — substitute your own context for `orbstack` below.

| Tool       | Version | Notes |
|------------|---------|-------|
| OrbStack k8s | v1.35.6+orb1 | Single-node cluster (server version; context `orbstack`). Also builds on v1.34.8+orb1. |
| kubectl    | v1.36.0 | Client; server is the OrbStack k8s version above. |
| helm       | v4.1.4  | Third-party components install via Helm. |
| istioctl   | 1.30.1  | Istio installs via `istioctl`, **not** Helm (see §3). |
| go         | 1.26.3  | Only needed to build the four service binaries. |
| docker     | 29.4.0  | Builds the four workload images (§4b). OrbStack shares this daemon with the cluster. |

Component pins, installed in §1–§4 (Go library pins live in
[`go.mod`](../go.mod)):

| Component | Version used |
|-----------|--------------|
| SPIRE | Helm chart 0.13.0 (server 1.7.2) |
| Istio | 1.30.1 |
| Tetragon | Helm chart 1.7.0 (agent v1.7.0) |
| kube-prometheus-stack | 86.2.0 (Grafana bundled) |

```sh
# OrbStack: enable the Kubernetes cluster, then confirm context
kubectl config use-context orbstack
kubectl get nodes        # expect one Ready node
```

Order matters: **SPIRE before Istio** (Istio's sidecars consume SPIRE's socket at
inject time), and **both before the workloads**.

The `helm repo add` lines in §1, §3 and §4 exit non-zero with `repository
name (...) already exists` if run before — harmless, but don't chain them
with `&&` since the following `helm repo update` still needs to run.

---

## 1. SPIRE (identity layer)

SPIRE server + spire-controller-manager + agent + SPIFFE CSI driver, as a
**single Helm release** named `spire` in namespace `spire-system` (chart
`spire-0.13.0`, SPIRE app `1.7.2`) — the controller-manager rides as a
sidecar in `spire-server-0`; no separate `spire-crds` release.

```sh
helm repo add spire https://spiffe.github.io/helm-charts-hardened/
helm repo update

helm upgrade --install spire spire/spire \
  -n spire-system --create-namespace --version 0.13.0
```

No `-f` / `--set` overrides: `helm get values spire -n spire-system` returns
`null` on this release — every value below (trust domain, socket name, the
default `ClusterSPIFFEID`) is the chart's own default at `0.13.0`.

> **No `spire-crds` pre-install is needed at `--version 0.13.0`** — verified
> against an empty cluster. The chart installs its own three
> `*.spire.spiffe.io` CRDs plus the `csi.spiffe.io` CSIDriver. The split into
> a separate `spire-crds` chart applies to the newer hardened charts (0.2x+),
> so it would bite if you drop the version pin.

Values that **must match the Istio overlay** (§2):

- Trust domain **`example.org`** — must equal `meshConfig.trustDomain`, or
  SVID SAN URIs won't validate and mTLS fails.
- Agent socket **`spire-agent.sock`** — the Istio overlay's
  `WORKLOAD_IDENTITY_SOCKET_FILE` must match this exact name.
- The chart's default `ClusterSPIFFEID`
  (`spire-controller-manager-service-account-based`) templates
  `spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}`
  with **no `podSelector`**, so it mints an SA-based SVID for every pod, not
  just labeled ones — the `spiffe.io/spire-managed-identity: "true"` label
  on Service A/B is currently a no-op. No manual `register-entry` step
  exists anywhere in this repo.

Verify:

```sh
kubectl get pods -n spire-system   # spire-server-0 (2/2), spire-agent (DaemonSet), spire-spiffe-csi-driver
kubectl get clusterspiffeid        # spire-controller-manager-service-account-based
```

On a cold install `spire-agent` restarts once (starts before the server
accepts attestation, then is Ready on retry ~a minute later) — wait for
`1/1` rather than reading the first `0/1` as a failure.

---

## 2. Istio (mesh layer, SPIRE-backed)

Installed from the checked-in overlay, which flips the trust domain and
registers the `spire` sidecar-injection template
(`deploy/istio/istio-operator.yaml`; [`docs/architecture.md`](architecture.md)
for *why*).

```sh
istioctl install -f deploy/istio/istio-operator.yaml -y
kubectl get pods -n istio-system                # istiod Ready
```

No Gateway is needed — all traffic in this lab is in-cluster (A → B).

---

## 3. Tetragon (detection layer)

```sh
helm repo add cilium https://helm.cilium.io/
helm repo update
helm upgrade --install tetragon cilium/tetragon \
  -n tetragon-system --create-namespace --version 1.7.0

kubectl rollout status -n tetragon-system ds/tetragon
```

**gRPC over TCP (required)** — the default chart serves `GetEvents` on a
Unix socket only, unreachable from the translator pod. Switch it to TCP with
the checked-in values file, then let the DaemonSet roll again:

```sh
helm upgrade tetragon cilium/tetragon -n tetragon-system --version 1.7.0 \
  --reuse-values -f deploy/tetragon/helm/values.yaml   # agent -> 0.0.0.0:54321

kubectl rollout status -n tetragon-system ds/tetragon
helm list -n tetragon-system      # CHART must still read tetragon-1.7.0
```

> **Repeat `--version 1.7.0` on the upgrade** — `--reuse-values` preserves
> values, not the chart version, and omitting it has silently moved the
> release off the pin before. Details in
> [`deploy/tetragon/README.md`](../deploy/tetragon/README.md).
> (`scripts/lab-up.sh` collapses both commands into a single pinned install
> with the values file — same end state, one DaemonSet roll.)

The TracingPolicies (one per scenario) are applied separately via
`make tetragon-apply`, which also publishes the `tetragon-grpc:54321`
Service the translator dials.

---

## 4. Prometheus + Grafana (observability)

```sh
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace --version 86.2.0
```

(Release `prometheus`, chart `kube-prometheus-stack-86.2.0`,
prometheus-operator `v0.91.0`.) ServiceMonitors and the latency dashboard
come later (`deploy/observability/`; `make observability-apply`).

Grafana access (not needed for the foundation): `make grafana-open`
port-forwards and prints the admin password
([`deploy/observability/README.md`](../deploy/observability/README.md)).

---

## 4b. Build the workload images

The workload manifests reference locally built images (`service-a:dev`,
`service-b:dev`, `translator:dev`, `actuator:dev`, no registry), which must
exist **before** §5 or the pods land in `ImagePullBackOff`. OrbStack shares
the daemon with the cluster — no load/push step:

```sh
make images        # docker build x4, tagged :dev
docker images | grep -E 'service-a|service-b|translator|actuator'   # expect four
```

`make build`, `make test`, and `make vet` run the local Go toolchain over
the same four services — no cluster needed.

---

## 5. Namespace + workloads

```sh
kubectl apply -f deploy/workloads/namespace.yaml   # carries istio.io/rev=default
make workloads-apply                                # A, B, translator, actuator, trial harness
```

Each of Service A and B carries, in its pod template:

- label `spiffe.io/spire-managed-identity: "true"` — currently a no-op (§1)
- annotation `inject.istio.io/templates: "sidecar,spire"` — runs the `spire`
  template alongside the default sidecar (§2)

The apps are plaintext HTTP on `:8080`; the sidecars do the mTLS.

### Mesh policies

STRICT mTLS, the A→B allow rule, and the revoked set are three separate
objects, applied here. Apply the allow rule before anything depends on
STRICT denials, or B briefly deny-alls.

```sh
kubectl apply -f deploy/istio/peer-authentication.yaml          # STRICT mTLS, namespace-wide
kubectl apply -f deploy/istio/authorization-policy-allow.yaml   # ALLOW A->B
kubectl apply -f deploy/istio/authorization-policy-deny-revoked.yaml  # the revoked set
```

> `revoked-identities` (the third one) **must exist before the first event,
> or the actuator's patch 404s** — the actuator appends principals to it
> rather than creating it (details in
> [`deploy/istio/README.md`](../deploy/istio/README.md), along with the
> SAN-vs-`principals:` check to run once the sidecars are up).

---

## 6. Verify the foundation

These four checks, in order, are the foundation's "done" definition.

**a. Sidecars injected (native sidecar = `initContainers`, so `READY 2/2`):**
```sh
kubectl get pods -n zta-ssf            # service-a / service-b show READY 2/2
```
Note: `-o jsonpath='{.spec.containers[*].name}'` will *not* list `istio-proxy`
under Istio 1.23+ — it lives in `initContainers[]`. Use `READY 2/2`.

**b. Envoy is sourcing certs from SPIRE, not istiod's Citadel** (the one-line proof):
```sh
POD=$(kubectl get pod -n zta-ssf -l app=service-a -o jsonpath='{.items[0].metadata.name}')
kubectl logs -n zta-ssf "$POD" -c istio-proxy | grep -i "workload SDS socket"
# Existing workload SDS socket found at var/run/secrets/workload-spiffe-uds/spire-agent.sock.
# Default Istio SDS Server will only serve files
```

**c. The cert on the wire is SPIRE's** (issuer + SAN URI):
```sh
istioctl proxy-config secret "$POD.zta-ssf" -o json \
  | python3 -c "import sys,json,base64,subprocess;d=json.load(sys.stdin);s=[x for x in d['dynamicActiveSecrets'] if x['name']=='default'][0];pem=base64.b64decode(s['secret']['tlsCertificate']['certificateChain']['inlineBytes']);subprocess.run(['openssl','x509','-noout','-issuer','-ext','subjectAltName'],input=pem)"
# issuer=C=NL, O=Example, CN=example.org      <- SPIRE CA, not istiod's O=cluster.local
# URI:spiffe://example.org/ns/zta-ssf/sa/service-a
```

**d. End-to-end traffic:**
```sh
kubectl logs -n zta-ssf "$POD" -c service-a --tail=5   # expect HTTP 200 from service-b on the loop
# time=... level=INFO msg=recv status=200 body="hello from service-b\n" rtt_us=494
```

---

## 7. Teardown

Reverse order; `make lab-down` runs the block below in one shot. Useful for
the destroy → rebuild → validate cycle.

**What this loses, permanently:**
- Prometheus's metrics history (the PVC-backed TSDB goes with the release).
- Any Grafana dashboard edit made only in the UI and never exported back
  into `deploy/observability/dashboard-revocation.json`; the checked-in JSON
  re-provisions on rebuild. The Grafana admin password rotates on reinstall.
- SPIRE's issued state (trust bundle, minted SVIDs) — reissued fresh on
  rebuild, as expected.

**What this does *not* touch:** trial CSVs and raw logs written by the
harness are local files, not cluster state, and are unaffected by a
teardown/rebuild.

```sh
make workloads-delete
kubectl delete -f deploy/workloads/namespace.yaml --ignore-not-found
istioctl uninstall -y --purge && kubectl delete ns istio-system
helm uninstall tetragon -n tetragon-system && kubectl delete ns tetragon-system
helm uninstall prometheus -n monitoring && kubectl delete ns monitoring
helm uninstall spire -n spire-system && kubectl delete ns spire-system
```

`make workloads-delete` already deletes the namespace, so the second line is
a no-op on a full teardown. Nothing else needs deleting by hand: mesh
policies (§5) go with the `zta-ssf` namespace, observability objects with
`monitoring`, the istiod ServiceMonitor with `istio-system`.
`make observability-delete` is only for partial teardowns where those
namespaces stay up.

`helm uninstall` does not remove CRDs — Tetragon's and prometheus-operator's
stay behind (Istio's are already gone via `--purge`). Harmless for a normal
rebuild; delete them too only for a genuinely empty cluster:

```sh
kubectl delete crd tracingpolicies.cilium.io tracingpoliciesnamespaced.cilium.io
kubectl delete crd alertmanagerconfigs.monitoring.coreos.com alertmanagers.monitoring.coreos.com \
  podmonitors.monitoring.coreos.com probes.monitoring.coreos.com \
  prometheusagents.monitoring.coreos.com prometheuses.monitoring.coreos.com \
  prometheusrules.monitoring.coreos.com scrapeconfigs.monitoring.coreos.com \
  servicemonitors.monitoring.coreos.com thanosrulers.monitoring.coreos.com
kubectl delete crd clusterfederatedtrustdomains.spire.spiffe.io clusterspiffeids.spire.spiffe.io \
  controllermanagerconfigs.spire.spiffe.io
```

---

## Beyond the foundation — doc map

§1–§6 stand up the **foundation**. The rest layers on in this order, each
step owned by its own runbook:

| Layer | Command | Runbook |
|---|---|---|
| Foundation | §1–§6 of this file | — |
| Workload images | `make images` (§4b) | this file |
| Mesh policies | the three `kubectl apply`s in §5 | [`deploy/istio/README.md`](../deploy/istio/README.md) |
| Detection | `make tetragon-apply` (needs the §3 TCP-gRPC upgrade) | [`deploy/tetragon/README.md`](../deploy/tetragon/README.md) |
| Observability | `make observability-apply`, then `make observability-targets` (expect five `up`) | [`deploy/observability/README.md`](../deploy/observability/README.md) |
| Trials | `make trial-smoke`, `make trial-run SCENARIO=exec COUNT=30` | [`docs/trial-reset.md`](trial-reset.md) |

Between §5 and `make tetragon-apply` the translator logs
`Failed to open GetEvents stream ... produced zero addresses` every five
seconds — the `tetragon-grpc` Service doesn't exist yet. It's a retry loop;
the stream opens itself once the Service is applied.
