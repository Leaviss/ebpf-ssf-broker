# Demo: revoke a compromised workload in real time

The whole loop, hands-on: Service A polls Service B in a steady loop over
SPIRE-issued mTLS. You play the attacker inside A. Within ~150 ms of the
attack syscall, the kernel match has been translated into a CAEP event and
A's identity is denied at B's sidecar — you watch its requests flip from
`200` to `403` live.


**You need:** a single-node Kubernetes cluster (OrbStack is the tested one),
`kubectl`, `helm`, `istioctl` **1.30.1**, and `docker`. Exact tool and
component pins are in [`docs/reproduce.md`](reproduce.md) §0 — match them
where you can.

## 1. Stand up the lab

```sh
make lab-up
```

One command: SPIRE → Istio (SPIRE-backed) → Tetragon → Prometheus → the four
workload images → workloads + mesh policies → scrape targets. It ends by
printing the `zta-ssf` pods; `service-a` and `service-b` should show
`READY 2/2`.

If a step fails, every one of them is annotated in
[`docs/reproduce.md`](reproduce.md) — find the matching section, fix, and
re-run `make lab-up` (it's idempotent).

## 2. Watch the victim

Keep this running in its own terminal — it's the whole show. The prober runs
fast (it's a measurement instrument), so rather than stream every line, this
refreshes the latest one once a second, and you'll watch its `status` flip in
place:

```sh
watch -n1 "kubectl logs -n zta-ssf -l 'app=service-a,variant!=trial' -c service-a --tail=10"
```

## 3. Attack

Open a shell inside the trial pod (it carries Service A's identity):

```sh
POD=$(kubectl get pod -n zta-ssf -l app=service-a,variant=trial -o name | head -1)
kubectl exec -it -n zta-ssf "$POD" -c service-a -- sh
```

From that shell, run the compromise — an in-pod exec of a network tool:

```sh
wget -qO- http://service-b.zta-ssf.svc.cluster.local:8080/ >/dev/null
```

(That's the `exec` scenario. `egress` and `token-read` one-liners are in
[`deploy/tetragon/README.md`](../deploy/tetragon/README.md) — which also
explains why the attack must run from the pod's own shell, not directly via
`kubectl exec <binary>`.)

## 4. Watch the revocation land

In the terminal from step 2, the single line flips `status=200` → `403`:

```
before:  ... msg=recv status=200 body="hello from service-b\n" ...
after:   ... msg=recv status=403 body="RBAC: access denied" ...
```

That's it — kernel policy match to identity denied at the enforcement point,
with no human in the loop. See the trail it left:

```sh
# A's SPIFFE ID is now in the mesh's revoked set
kubectl get authorizationpolicy revoked-identities -n zta-ssf \
  -o jsonpath='{.spec.rules[0].from[0].source.principals}' && echo

# The pipeline's own account: event received -> SET minted -> policy patched
kubectl logs -n zta-ssf -l app=translator -c translator --tail=5
kubectl logs -n zta-ssf -l app=actuator   -c actuator   --tail=5
```

## 5. Run it again

State survives a trial (the deny rule, the actuator's dedupe set), so reset
before re-attacking — details in [`docs/trial-reset.md`](trial-reset.md):

```sh
make trial-reset
```

Then repeat step 3 with any scenario. Or let the harness do a full
measured lap of all three, printing a timing row per trial:

```sh
make trial-smoke
```

For the dashboard view, `make grafana-open` and look for **ZTA Revocation**.

## 6. Tear down

```sh
make lab-down
```

Reverse of `lab-up`; what it deletes (and deliberately leaves behind) is in
[`docs/reproduce.md`](reproduce.md) §7.

## Where to next

- **How it works** — [`docs/architecture.md`](architecture.md): the four
  layers and how a detection becomes a deny.
- **The numbers** — the ~150 ms you just watched held across 300 measured
  trials: [Results (TL;DR)](../README.md#results-tldr) in the README.
