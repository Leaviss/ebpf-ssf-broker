#!/usr/bin/env bash
# Stand up the whole lab on the current kubectl context, from empty cluster to
# "attack it and watch the deny land".
#
#   make lab-up        # or: scripts/lab-up.sh
#
# Automates docs/reproduce.md §1–§5 plus detection and observability, with the
# same pinned chart versions. The guided walkthrough is docs/demo.md; the
# fully annotated version of every step (what it installs, why, what can go
# wrong) is docs/reproduce.md — go there when a step here fails.
#
# One deliberate difference from reproduce.md §3: Tetragon is installed in a
# single `helm upgrade --install` with the TCP-gRPC values file, instead of
# the manual install-then-upgrade — same end state, one DaemonSet roll.
set -euo pipefail

KUBECTL=${KUBECTL:-kubectl}
HELM=${HELM:-helm}
NAMESPACE=${NAMESPACE:-zta-ssf}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

step() { printf '\n=== %s\n' "$*"; }

step "Target cluster: $($KUBECTL config current-context)"
$KUBECTL get nodes

# `|| true`: `helm repo add` exits non-zero if the repo name already exists
# (docs/reproduce.md §0) — harmless on a re-run.
step "§1 SPIRE (chart 0.13.0)"
$HELM repo add spire https://spiffe.github.io/helm-charts-hardened/ 2>/dev/null || true
$HELM repo add cilium https://helm.cilium.io/ 2>/dev/null || true
$HELM repo add prometheus-community https://prometheus-community.github.io/helm-charts 2>/dev/null || true
$HELM repo update

$HELM upgrade --install spire spire/spire \
  -n spire-system --create-namespace --version 0.13.0
$KUBECTL rollout status -n spire-system statefulset/spire-server --timeout=300s
# On a cold install spire-agent restarts once before going Ready
# (docs/reproduce.md §1) — the wait below rides that out.
$KUBECTL rollout status -n spire-system ds/spire-agent --timeout=300s

step "§2 Istio (SPIRE-backed, from the checked-in overlay)"
istioctl install -f deploy/istio/istio-operator.yaml -y

step "§3 Tetragon (chart 1.7.0, gRPC on TCP) + detection policies"
$HELM upgrade --install tetragon cilium/tetragon \
  -n tetragon-system --create-namespace --version 1.7.0 \
  -f deploy/tetragon/helm/values.yaml
$KUBECTL rollout status -n tetragon-system ds/tetragon --timeout=300s
make tetragon-apply    # 3 emit-only TracingPolicies + tetragon-grpc Service

step "§4 Prometheus + Grafana (kube-prometheus-stack 86.2.0)"
$HELM upgrade --install prometheus prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace --version 86.2.0

step "§4b Workload images (local docker build, tagged :dev)"
make images

step "§5 Namespace + workloads + mesh policies"
$KUBECTL apply -f deploy/workloads/namespace.yaml
make workloads-apply
$KUBECTL apply -f deploy/istio/peer-authentication.yaml
$KUBECTL apply -f deploy/istio/authorization-policy-allow.yaml
$KUBECTL apply -f deploy/istio/authorization-policy-deny-revoked.yaml

step "Scrape targets + dashboard (deploy/observability/README.md)"
$KUBECTL wait --for condition=Established --timeout=120s \
  crd/podmonitors.monitoring.coreos.com crd/servicemonitors.monitoring.coreos.com
make observability-apply

step "Waiting for the workloads"
for d in $($KUBECTL get deploy -n "$NAMESPACE" -o name); do
  $KUBECTL rollout status -n "$NAMESPACE" "$d" --timeout=300s
done

step "Lab is up"
$KUBECTL get pods -n "$NAMESPACE"
printf '\nNext: docs/demo.md step 2 — watch Service A talk to B, then attack it.\n'
