# deploy/istio

Istio config for the mesh-enforcement architecture.

| File | Purpose | Lifecycle |
|------|---------|-----------|
| `istio-operator.yaml` | IstioOperator overlay; mounts the SPIFFE CSI Workload API socket into each `istio-proxy` so sidecars fetch SVIDs from SPIRE via SDS | install-time |
| `peer-authentication.yaml` | STRICT mTLS, namespace-wide | always on |
| `authorization-policy-allow.yaml` | ALLOW A→B (and implicitly deny every other identity at B) | always on |
| `authorization-policy-deny-revoked.yaml` | The revoked set (docs/architecture.md, "How revocation works"). Seeded with a placeholder principal; the actuator JSON-patches real principals onto it at runtime | apply once, then actuator-owned |

## Baseline policy, and the manual revocation proof

```sh
# 1. Turn on STRICT mTLS + the allow rule. Apply allow BEFORE depending on
#    STRICT denials, or B briefly deny-alls once a selector is in play.
kubectl apply -f deploy/istio/peer-authentication.yaml
kubectl apply -f deploy/istio/authorization-policy-allow.yaml
#    -> A→B works; mTLS is now mandatory (plaintext peers rejected).

# 2. Apply the deny -> A blocked at B's sidecar (DENY is evaluated before ALLOW).
kubectl apply -f deploy/istio/authorization-policy-deny-revoked.yaml
#    -> A→B now returns 403 / RBAC denied.

# 3. Delete the deny -> A allowed again. This apply/delete toggle IS the proof.
kubectl delete -f deploy/istio/authorization-policy-deny-revoked.yaml
```

Re-apply the deny manifest afterwards: the actuator patches that object and
404s if it is missing.

## The actuator owns the deny policy

Outside that manual proof, `authorization-policy-deny-revoked.yaml` is the
*starting state* the actuator appends to (`cmd/actuator/mesh.go`, JSON patch
on `spec.rules[0].from[0].source.principals`) — it must exist before the
first event or the patch 404s. The seeded principal is a placeholder
matching no SVID; the list can't start empty since Istio rejects a `source`
with no fields.

```sh
# Reset the revoked set between trials (re-apply = back to placeholder-only).
kubectl apply -f deploy/istio/authorization-policy-deny-revoked.yaml

# Watch the revoked set grow as the actuator patches it.
kubectl get authorizationpolicy revoked-identities -n zta-ssf \
  -o jsonpath='{.spec.rules[0].from[0].source.principals}' && echo
```

## Verify the SAN matches `principals:`

The `principals:` strings are version-sensitive (SPIRE↔Istio SDS wiring) —
confirm the SVID's URI SAN equals `example.org/ns/zta-ssf/sa/service-a`, and
fix `principals:` in both AuthorizationPolicies if it differs.

```sh
# Inspect the SVID B's sidecar holds / presents.
istioctl proxy-config secret deploy/service-b -n zta-ssf -o json \
  | jq -r '.dynamicActiveSecrets[].secret.tlsCertificate.certificateChain.inlineBytes' \
  | base64 -d | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
```

A mismatched SAN fails silently — the deny just won't match and A stays allowed.
