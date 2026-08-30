# Resetting between attack scenarios

A trial mutates state in four places; three survive the trial and silently
corrupt the next one if not cleared. Trigger steps live in
[`deploy/tetragon/README.md`](../deploy/tetragon/README.md) — this file is
what to run *after*.

---

## What a trial leaves behind

| State | Where it lives | Survives | Cleared by |
|---|---|---|---|
| Revoked principal appended to the DENY policy | `AuthorizationPolicy/revoked-identities` | everything | re-apply the manifest |
| `revoked` dedupe set (`sync.Map`, `cmd/actuator/mesh.go`) | actuator process memory | pod stays up | `POST /admin/reset-dedupe` — **not** a restart, see below |
| `spiffe.io/spire-managed-identity` stripped | the live A pods, not the Deployment template | pod stays up | pod recreate |
| Warm mTLS connection + issued SVID | A's `istio-proxy` | policy reset | pod recreate |
| Attacker artifacts (shell history, files, stray `nc`) | trial pod filesystem | pod stays up | pod recreate |
| Tetragon / translator | nothing — stateless today | — | restart only for a clean log boundary |

**The dedupe set is the dangerous one.** `revokeInMesh` skips the patch for a
subject already revoked, so re-running a scenario against a still-running
actuator logs `Subject already revoked, skipping mesh patch` and measures
nothing — quietly, looking like a detection failure.

**Do not clear it by restarting the actuator.** A replacement pod lives
about as long as a trial (~12 s), so most trials are never scraped after
their PATCH — one measured exec run had Prometheus recording 19 of 29
revocations while the CSV had all 29. The actuator
must outlive the run; the set is cleared in place over HTTP.

---

## The reset

```sh
make trial-reset
```

Or by hand, in this order:

```sh
# 1 — mesh: restore the seeded revoked set. A CRD, so kubectl apply replaces
#     the principals list wholesale, not merged.
kubectl apply -f deploy/istio/authorization-policy-deny-revoked.yaml

# 2 — actuator: drop the in-memory dedupe set in place. Do NOT restart it (see above).
scripts/actuator-reset.sh          # or: make actuator-reset

# 3 — translator: clean log boundary — load-bearing, since trial_record.py
#     uses its first line to bound the trial inside the actuator's own log.
kubectl rollout restart deployment/translator -n zta-ssf

# 4 — Service A: restores the pod label, fresh SVID + connections, wipes artifacts.
kubectl rollout restart deployment/service-a       -n zta-ssf
kubectl rollout restart deployment/service-a-trial -n zta-ssf

kubectl rollout status deployment/translator      -n zta-ssf --timeout=60s
kubectl rollout status deployment/service-a       -n zta-ssf --timeout=60s
kubectl rollout status deployment/service-a-trial -n zta-ssf --timeout=60s
```

Order matters only in that the policy reset (1) precedes the pod recreate
(4) — otherwise the new pods come up briefly denied, muddying the logs.
Service B is deliberately **not** restarted: its identity is never revoked,
and Envoy re-evaluates RBAC per request, so the policy reset takes effect on
the existing connection.

---

## Verify clean

```sh
# a. Revoked set is back to the placeholder alone.
kubectl get authorizationpolicy revoked-identities -n zta-ssf \
  -o jsonpath='{.spec.rules[0].from[0].source.principals}'; echo
# → ["example.org/ns/zta-ssf/sa/placeholder-never-matches"]

# b. Both A pods carry the SPIRE label again.
kubectl get pods -n zta-ssf -l app=service-a -L spiffe.io/spire-managed-identity,variant
# → SPIRE-MANAGED-IDENTITY = true on each

# c. SPIRE has one entry per A pod (entries are pod-uid scoped).
kubectl exec -n spire-system spire-server-0 -c spire-server -- \
  /opt/spire/bin/spire-server entry show \
  -spiffeID spiffe://example.org/ns/zta-ssf/sa/service-a | grep -c "Entry ID"
# → one per running A pod (2 with service-a-trial at 1 replica)

# d. A→B is 200 again.
kubectl logs -n zta-ssf -l 'app=service-a,variant!=trial' -c service-a --tail=3
# → recv status=200 body="hello from service-b\n" rtt=...
```

Only (a) and (d) are strictly required. (b) and (c) confirm the complementary
half of the response — see the caveat below.

---

## Before the first trial

The actuator image must contain `cmd/actuator/mesh.go` +
`cmd/actuator/labels.go`. OrbStack shares the Docker daemon, so a local
build suffices — no image load step:

```sh
make image-actuator
kubectl rollout restart deployment/actuator -n zta-ssf
```

---

## Caveat — label removal is currently inert

The `ClusterSPIFFEID` installed by the SPIRE Helm chart has **no
`podSelector`**:

```sh
kubectl get clusterspiffeid spire-controller-manager-service-account-based -o jsonpath='{.spec}'
# → {"spiffeIDTemplate":"spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}"}
```

It mints an entry for *every* pod regardless of the label — even unlabeled
`c2-sink` has one. The actuator's label removal succeeds, but the
registration entry stays alive: the renewal cutoff in docs/architecture.md
doesn't actually happen yet. This doesn't affect the measured result (the
mesh deny is the revocation), but verify step (c) will show the entry still
present after a trial.

Making the label load-bearing would mean adding a matching `podSelector`
through the SPIRE release's values (a live `kubectl patch` would be reverted
on the next `helm upgrade`) — at the cost of every unlabeled pod in the
cluster losing its SVID.

---

## Pooled connections

A's steady probe loop keeps the A→B connection warm, but the mesh deny is
evaluated per request so it lands regardless. If a trial ever shows the deny
not taking on the existing connection, restarting B forces a fresh handshake
and disambiguates — that's a pooled-connection limitation, not a reset
failure.
