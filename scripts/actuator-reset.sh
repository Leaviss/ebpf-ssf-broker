#!/usr/bin/env bash
# Clear the actuator's in-memory dedupe set without restarting it.
#
#   scripts/actuator-reset.sh
#
# The alternative — `kubectl rollout restart deployment/actuator` — costs the
# measurement: the trial then runs in an actuator pod that lives about as long as
# the trial itself (~12s at the observed cadence). Against a scrape interval most
# pods are scraped once or not at all, and a single scrape is a coin flip on
# whether it landed before or after the PATCH: one measured exec run recorded 19
# of 29 revocations in Prometheus while the CSV had all 29 (docs/trial-reset.md).
# A counter is only meaningful if the process holding it outlives what it counts.
#
# The endpoint is on the metrics listener (:9091), not the :9090 SET receiver:
# 9091 already carries traffic.sidecar.istio.io/excludeInboundPorts, so it is
# outside the mesh and a port-forward reaches it without mTLS, while the
# measured path on :9090 stays untouched.
set -euo pipefail

NAMESPACE=${NAMESPACE:-zta-ssf}
KUBECTL=${KUBECTL:-kubectl}
METRICS_PORT=${METRICS_PORT:-9091}
# Local port is deliberately not 9091: the trial harness may be running
# alongside other port-forwards, and a collision here would fail a reset
# silently enough to look like a dedupe bug.
LOCAL_PORT=${LOCAL_PORT:-19091}
PATH_RESET=${PATH_RESET:-/admin/reset-dedupe}
READY_TIMEOUT=${READY_TIMEOUT:-15}

$KUBECTL port-forward -n "$NAMESPACE" deployment/actuator \
  "${LOCAL_PORT}:${METRICS_PORT}" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null' EXIT

# Poll rather than sleep a fixed interval: this runs once per trial, so a
# hardcoded 4s would add two minutes to a 30-trial run.
deadline=$((SECONDS + READY_TIMEOUT))
until curl -fsS -o /dev/null "http://localhost:${LOCAL_PORT}/metrics" 2>/dev/null; do
  if ! kill -0 $pf 2>/dev/null; then
    echo "  ! port-forward to deployment/actuator died" >&2
    exit 1
  fi
  if (( SECONDS >= deadline )); then
    echo "  ! actuator metrics endpoint not reachable within ${READY_TIMEOUT}s" >&2
    exit 1
  fi
  sleep 0.2
done

# POST, not GET — the handler rejects anything else so a stray scrape of this
# listener cannot clear the set mid-trial.
if ! out=$(curl -fsS -X POST "http://localhost:${LOCAL_PORT}${PATH_RESET}" 2>&1); then
  echo "  ! reset failed: $out" >&2
  echo "  ! is the actuator image current? older images have no ${PATH_RESET}" >&2
  exit 1
fi

echo "actuator dedupe set: ${out:-cleared}"
