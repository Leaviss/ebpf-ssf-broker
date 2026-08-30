# ebpf-ssf-broker

> [!CAUTION] 
> This is a research artifact from a master's thesis, built and measured on a
> single-node lab cluster. It is not production software — see
> [Example Lab-only caveats](#example-lab-only-caveats).

Real-time workload identity revocation in Kubernetes: a SPIFFE/SPIRE identity
broker fed by eBPF runtime signals (Tetragon), normalized into CAEP events,
driving deterministic access revocation for a compromised non-human workload.

**The research question:** how effectively can such a broker translate workload
telemetry into real-time revocation, and how fast and repeatable is the
loop? Short answer: deterministically, in ~150 ms — see
[Results (TL;DR)](#results-tldr).

**Choose your adventure:**

- **Run it** — [`docs/demo.md`](docs/demo.md): `make lab-up`, trigger a
  compromise, watch the deny land live.
- **Understand the design** — [`docs/architecture.md`](docs/architecture.md).

## How it works

A Tetragon TracingPolicy matches a compromise signal inside Service A
(exec / egress / token-read) and emits the event — no in-kernel response.
The translator resolves the subject SPIFFE ID and mints a CAEP-conformant
SET; the actuator patches a deny for that identity into an Istio
`AuthorizationPolicy` and, in parallel, strips the SPIRE pod label to block
reissuance. Service B's istio-proxy then rejects Service A per-request —
including on warm, pooled connections. Enforcement lives in the mesh, not
SPIRE: an already-issued SVID stays valid until its TTL expires. Full flow
and conceptual map in [`docs/architecture.md`](docs/architecture.md).

## Results (TL;DR)

Measured over 300 launched trials, 100 per compromise scenario
(exec / egress / token-read), on the single-node lab:

- **Every valid trial revoked — 296/296** (4 excluded: the compromise never
  executed, so there was nothing to detect).
- **~147 ms median end to end**, kernel policy match → first denied request
  at Service B's sidecar (p95 ≈ 161 ms, sd ≈ 10 ms). The broker pipeline
  itself accounts for a median of ~14 ms; the rest is Istio config
  propagation.
- **Baseline contrast:** deleting the compromised workload's SPIRE entry left
  a warm connection authenticating for 8+ minutes — the broker-mediated deny
  is a three-to-four-order-of-magnitude reduction in exposure.

The full per-trial dataset (`trials.csv`) and raw logs remain available at
the [v1.0.0 release](https://github.com/Leaviss/ebpf-ssf-broker/releases/tag/v1.0.0).

## Components

| Path | Role |
|------|------|
| `cmd/service-a/` | Dummy compromised caller. Plaintext HTTP probe loop to B; its sidecar holds the SPIRE SVID and does mTLS. |
| `cmd/service-b/` | Dummy callee and enforcement point — its sidecar terminates mTLS and denies revoked identities. |
| `cmd/translator/` | Consumes the Tetragon gRPC stream, resolves the subject SPIFFE ID, mints a CAEP SET, POSTs it to the actuator ([RFC 8935](https://www.rfc-editor.org/rfc/rfc8935)). |
| `cmd/actuator/` | Consumes [CAEP](https://openid.net/specs/openid-caep-1_0.html) events: `labels.go` strips the SPIRE pod label, `mesh.go` patches the revocation into `AuthorizationPolicy`. |
| `internal/caep/` | SET ([RFC 8417](https://www.rfc-editor.org/rfc/rfc8417)) encoding with CAEP event types. |
| `internal/metrics/` | Shared Prometheus histogram buckets + `/metrics` listener. |
| `deploy/` | K8s manifests: SPIRE notes, Istio overlay + policies, emit-only Tetragon TracingPolicies (one per scenario), workloads, observability. |
| `scripts/` | Trial harness: run a scenario, reset state, join logs into one CSV row per trial. |
| `test/fixtures/` | Captured Tetragon event JSON for unit-testing the translator. |

## Tools

| Tool | Role |
|------|------|
| [OrbStack](https://orbstack.dev/) | Single-node Kubernetes cluster this lab was built and measured on. |
| [kubectl](https://kubernetes.io/docs/reference/kubectl/) | Cluster CLI. |
| [Helm](https://helm.sh/) | Installs SPIRE, Tetragon, and kube-prometheus-stack. |
| [Istio](https://istio.io/) ([istioctl](https://istio.io/latest/docs/reference/commands/istioctl/)) | Service mesh; enforces the deny at the sidecar. |
| [SPIFFE/SPIRE](https://spiffe.io/) | Workload identity — issues and rotates the SVIDs mTLS runs on. |
| [Tetragon](https://tetragon.io/) | eBPF runtime observability; source of the compromise signal. |
| [Prometheus](https://prometheus.io/) / [Grafana](https://grafana.com/) | Metrics and the `ZTA Revocation` dashboard (via kube-prometheus-stack). |
| [k9s](https://k9scli.io/) | Optional — terminal UI for poking around the cluster live during a trial. |
| [Go](https://go.dev/) | Builds the four service binaries. |
| [Docker](https://www.docker.com/) | Builds the workload images. |

Exact version pins are in [`docs/reproduce.md`](docs/reproduce.md) §0.

## Example Lab-only caveats

Deliberate simplifications, named so nobody mistakes them for a production
pattern:

- **SETs are unsigned JWTs (`alg: none`)** (`internal/caep/set.go`) — the
  translator→actuator hop relies on transport integrity, not a JWS signature.
- **`/admin/reset-dedupe` is unauthenticated**, deliberately outside the mesh
  so the trial harness can reach it (`cmd/actuator/main.go`).
- **The trust domain `example.org` is hardcoded** in the translator,
  matching the SPIRE Helm-chart default.
- Detection is a fixed Tetragon policy match — a match *is* the verdict, with
  no multi-signal correlation, ML, or judgment in the actuator.

