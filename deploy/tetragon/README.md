# deploy/tetragon

Tetragon TracingPolicy manifests — **emit-only** (no in-kernel response
actions). Tetragon is the sensor; the response is identity revocation in the
mesh, and in-kernel SIGKILL is out of scope (docs/architecture.md).

One policy per compromise scenario:

- [`tracingpolicy-exec.yaml`](./tracingpolicy-exec.yaml) — scenario 1: anomalous
  process execution (curl/wget/sh exec inside Service A).
- [`tracingpolicy-egress.yaml`](./tracingpolicy-egress.yaml) — scenario 2:
  unexpected network egress (simulated C2 callback).
- [`tracingpolicy-token-read.yaml`](./tracingpolicy-token-read.yaml) — scenario 3:
  credential abuse (service-account-token read by a non-sidecar, non-app binary).

Apply: `make tetragon-apply`. Delete: `make tetragon-delete`.

All three feed the same translator with the same `process_kprobe` event
envelope; they differ only in which kernel hook fires.

## gRPC prerequisite (one-time)

The translator consumes the agent's gRPC `GetEvents` stream, which the
default chart serves only on a Unix socket, unreachable from the translator
pod. Switch it to TCP and expose it once:

```sh
helm upgrade tetragon cilium/tetragon -n tetragon-system --version 1.7.0 \
  --reuse-values -f deploy/tetragon/helm/values.yaml   # agent -> 0.0.0.0:54321
make tetragon-apply                                     # applies grpc-service.yaml too
```

`--version 1.7.0` is required, not optional — without it `helm upgrade`
resolves the repo's current latest and silently moves the release off the
pinned chart (observed on the validation run: revision 2 landed on chart
1.7.1). `--reuse-values` carries values forward, not the chart version.

`grpc-service.yaml` (Service `tetragon-grpc:54321`) ships in this dir, so
`make tetragon-apply` publishes it alongside the policies. The translator dials
`tetragon-grpc.tetragon-system.svc.cluster.local:54321`.

## Running the scenarios

Bring up the sensors and the trial harness:

```sh
make tetragon-apply     # 3 policies + tetragon-grpc Service
make workloads-apply    # includes service-a-trial (attacker vehicle) + c2-sink
```

**Trigger from the pod's own shell — not `kubectl exec <binary>` directly.**
A direct `kubectl exec` execs under `/usr/bin/.runc`, whose empty
`process.pod` can't be resolved to a SPIFFE ID (`test/fixtures/README.md`
caveat 1); a child of the pod's shell reproduces a real in-process-tree
compromise. Open a shell in one trial pod:

```sh
POD=$(kubectl get pod -n zta-ssf -l app=service-a,variant=trial -o name | head -1)
kubectl exec -it -n zta-ssf "$POD" -c service-a -- sh
```

Then, from inside that shell, run one line per scenario:

```sh
# Scenario 1 — anomalous exec (emit-exec-service-a): matches /wget|/sh|/curl.
wget -qO- http://service-b.zta-ssf.svc.cluster.local:8080/ >/dev/null

# Scenario 2 — C2 egress (emit-egress-service-a): matches DPort 9666.
#   tcp_connect fires twice — once for /bin/wget, once for Envoy's upstream.
wget -qO- http://c2-sink.zta-ssf.svc.cluster.local:9666/ >/dev/null

# Scenario 3 — SA-token read (emit-token-read-service-a): non-sidecar/app read.
cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null
```

Watch matches land in the translator:

```sh
kubectl logs -n zta-ssf -l app=translator -c translator -f
```

Each scenario yields one or more `Received ProcessKprobe event` lines.
Expect **duplicates** (scenario 2 emits two connects; a token read can fire
twice) — revocation is per-identity and idempotent, so the translator
dedupes per resolved SPIFFE ID.
