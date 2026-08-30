# test/fixtures

Captured Tetragon `process_kprobe` event JSON, used as inputs to the translator's
unit tests. The translator is a pure function over these fixtures — no cluster
needed to test it.

Captured 2026-07-05 from the live OrbStack cluster (Tetragon v1.7.0), with
the three emit-only TracingPolicies (`deploy/tetragon/`) applied and the
trial harness running. Each scenario was triggered from an in-pod shell so
every event is pod-attributed (caveat 1). Selected with
`tetra getevents --policy-names emit-exec-service-a,emit-egress-service-a,emit-token-read-service-a`.

| Fixture | Policy | Hook | What it represents |
|---------|--------|------|--------------------|
| [`exec-wget.json`](./exec-wget.json) | `emit-exec-service-a` | `__arm64_sys_execve` | In-pod shell (`/bin/sh`) exec'ing a network tool; the matched pathname is in `args[0].string_arg` = `/bin/wget`. |
| [`egress-c2-callback.json`](./egress-c2-callback.json) | `emit-egress-service-a` | `tcp_connect` | Service A's **own** C2 callback to `:9666` (`binary: /bin/wget`, `sock_arg.dport: 9666`). |
| [`token-read-sa-token.json`](./token-read-sa-token.json) | `emit-token-read-service-a` | `security_file_permission` | `/bin/cat` reading the SA token; `args[0].file_arg.path` + `args[1].int_arg: 4` (MAY_READ). |

No secrets in the fixtures: the token-read event carries only the file *path* and
mode, never contents.

## Caveats the translator must handle (empirical)

1. **Pod attribution requires an in-pod parent.** A direct `kubectl exec
   <binary>` runs under `runc` with an **empty `pod` object**, unresolvable
   to a SPIFFE ID; only children of the pod's own process tree carry
   `process.pod`. Treat a missing `process.pod` as unresolvable, not a crash.

2. **Resolve the SPIFFE ID from the `app` pod label, not `workload`.** The
   SPIFFE ID is ServiceAccount-based, but `process.pod.workload` is the
   *Deployment* name (`service-a-trial` here) — not the SA, which the event
   carries no field for. Use `process.pod.namespace` +
   `process.pod.pod_labels["app"]` (= `service-a`), the stable selector
   SPIRE entries key on (docs/architecture.md).

3. **Egress emits two events per callback** — the app's own connect and
   Envoy's upstream connect both fire on `:9666`. Only the app-origin one is
   committed; both carry identical pod metadata and resolve to the same
   identity, so dedupe per identity.
