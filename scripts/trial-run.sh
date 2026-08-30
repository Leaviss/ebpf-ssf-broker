#!/usr/bin/env bash
# Run one attack scenario end to end and record a per-trial CSV row.
#
#   scripts/trial-run.sh <exec|egress|token-read> [-n COUNT] [--no-reset] [--note TEXT]
#
# Sequence per trial (docs/trial-reset.md):
#   reset -> confirm a clean 200 baseline -> trigger -> wait for the revocation
#   and the deny -> capture raw logs -> join them into one CSV row.
#
# Raw logs are kept per trial under RAW_ROOT/<trial_id>/ so every recorded
# number is reproducible from the evidence, not just from the CSV. The defaults
# (results/test-trials.csv, results/raw-test/) are throwaway local output —
# point CSV= / RAW_ROOT= elsewhere for a run you intend to keep.
# No `pipefail`. Every check below is `kubectl logs | grep -q`, and grep -q exits
# at the first match — which SIGPIPEs kubectl mid-write and makes the pipeline
# exit 141. Under pipefail a *successful* find therefore reads as a failure, and
# only for matches early in a long log: the 200-baseline check timed out for the
# full 60 s while the prober was logging 200s the whole time, because that match
# is at line 3 of a 3,000-line log. The 403 and revoked checks match near the end
# and never tripped it.
set -u

NAMESPACE=${NAMESPACE:-zta-ssf}
KUBECTL=${KUBECTL:-kubectl}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CSV=${CSV:-$ROOT/results/test-trials.csv}
RAW_ROOT=${RAW_ROOT:-$ROOT/results/raw-test}

# How long to wait for the pipeline to produce each half of the measurement.
# Generous: the in-code pipeline is ~10 ms and `enforce` is the unknown being
# measured, so a timeout here is a finding to investigate, not a tuning knob.
REVOKE_TIMEOUT=${REVOKE_TIMEOUT:-60}
DENY_TIMEOUT=${DENY_TIMEOUT:-60}

usage() { sed -n '2,12p' "$0"; exit 2; }

SCENARIO=${1:-}
[[ -n $SCENARIO ]] || usage
shift

COUNT=1
RESET=1
NOTE=""
while [[ $# -gt 0 ]]; do
  case $1 in
    -n) COUNT=$2; shift 2 ;;
    --no-reset) RESET=0; shift ;;
    --note) NOTE=$2; shift 2 ;;
    *) usage ;;
  esac
done

# Trigger commands are the ones documented in deploy/tetragon/README.md. They
# run under `sh -c` rather than as a direct `kubectl exec <binary>`: a direct
# exec runs under /usr/bin/.runc, whose process.pod is empty, so the event
# carries no namespace or labels and cannot be resolved to a SPIFFE ID
# (see deploy/tetragon/README.md).
case $SCENARIO in
  exec)       TRIGGER='wget -qO- http://service-b.zta-ssf.svc.cluster.local:8080/ >/dev/null' ;;
  egress)     TRIGGER='wget -qO- http://c2-sink.zta-ssf.svc.cluster.local:9666/ >/dev/null' ;;
  token-read) TRIGGER='cat /var/run/secrets/kubernetes.io/serviceaccount/token >/dev/null' ;;
  *) echo "unknown scenario: $SCENARIO" >&2; usage ;;
esac

# --tail=-1 is not optional: `kubectl logs -l` defaults to --tail=10, which
# would silently truncate away the very first 403 — the one T8 is taken from.
logs_of() {
  $KUBECTL logs -n "$NAMESPACE" -l "$1" -c "$2" --tail=-1 2>/dev/null
}
prober_logs()    { logs_of 'app=service-a,variant!=trial' service-a; }
actuator_logs()  { logs_of 'app=actuator' actuator; }
translator_logs(){ logs_of 'app=translator' translator; }

wait_for() { # wait_for <timeout_s> <description> <cmd...>
  local timeout=$1 what=$2; shift 2
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  echo "  ! timed out after ${timeout}s waiting for ${what}" >&2
  return 1
}

# The actuator is not restarted between trials (Makefile: trial-reset), so its
# log accumulates over the whole run and `grep -q result=revoked` would match
# trial 1's line instantly on every later trial — the wait would return before
# this trial had revoked anything. Count instead, and wait for the count to rise
# above what it was before the trigger. `grep -c` reads the whole stream, so the
# SIGPIPE caveat in the header does not apply to it.
revoked_count()  { actuator_logs | grep -c 'result=revoked'; }
has_revocation() { (( $(revoked_count) > revoked_before )); }

# The prober is still restarted per trial, so its log starts empty and a plain
# match is safe for both of these.
has_deny()       { prober_logs   | grep -q 'msg=recv status=403'; }
has_baseline()   { prober_logs   | grep -q 'msg=recv status=200'; }

for ((i = 1; i <= COUNT; i++)); do
  echo "=== ${SCENARIO} trial ${i}/${COUNT} ==="
  trial_note=$NOTE

  if (( RESET )); then
    echo "--- reset ---"
    if ! make -C "$ROOT" --no-print-directory trial-reset >/dev/null 2>&1; then
      echo "  ! trial-reset failed; see 'make trial-reset'" >&2
      exit 1
    fi
  fi

  # A trial with no clean 200 baseline measures nothing: if A is already denied
  # then the "first 403" is the previous trial's, not this one's.
  if ! wait_for 60 "a 200 baseline from the prober" has_baseline; then
    trial_note="${trial_note:+$trial_note; }no 200 baseline before trigger"
  fi

  # Let the rollout `trial-reset` kicked off finish before naming a pod. The
  # baseline gate above does not cover this: it polls the prober, which is a
  # different Deployment (variant!=trial), so the trial pod's readiness goes
  # unchecked otherwise.
  if (( RESET )); then
    $KUBECTL rollout status deployment/service-a-trial -n "$NAMESPACE" \
      --timeout=120s >/dev/null 2>&1 \
      || echo "  ! service-a-trial rollout did not converge" >&2
  fi

  # Running, and not already terminating. A bare `.items[0]` matches both the
  # terminating pod and its replacement during a rollout, and kubectl sorts list
  # items by name, so which one it returns is a coin flip on the ReplicaSet hash.
  # Picking the doomed one makes the trigger exec fail with NotFound once that pod
  # finishes terminating — a miss whose evidence is identical to a dropped
  # Tetragon event, and the single cause of the 4/300 exclusions on the published
  # run. A phase filter
  # alone is not enough: a terminating pod stays in phase Running until it is gone.
  POD=$($KUBECTL get pod -n "$NAMESPACE" -l app=service-a,variant=trial \
        --field-selector=status.phase=Running \
        -o go-template='{{range .items}}{{if not .metadata.deletionTimestamp}}{{.metadata.name}}{{"\n"}}{{end}}{{end}}' \
        2>/dev/null | head -1)
  if [[ -z $POD ]]; then
    echo "  ! no running service-a-trial pod (make workloads-apply)" >&2
    exit 1
  fi

  # Sampled after the reset and immediately before the trigger, so has_revocation
  # waits for a revocation caused by *this* trial.
  revoked_before=$(revoked_count)

  echo "--- trigger (${SCENARIO}) in ${POD} ---"
  # The exit status is checked rather than discarded. A trigger that never ran
  # and a Tetragon event that never arrived leave identical evidence behind — an
  # empty translator log, an untouched actuator, an all-200 prober — so a
  # `no_revocation` trial otherwise has three indistinguishable causes: the exec
  # failed, the TracingPolicy did not match, or the event was dropped on the
  # gRPC stream. Recording the exec's own failure here removes the one cause
  # that belongs to the harness, so the remaining misses can be attributed to
  # the sensor. stderr is captured, not printed,
  # because `kubectl exec` reports the interesting part of the failure there.
  trigger_err=$($KUBECTL exec -n "$NAMESPACE" "$POD" -c service-a -- \
                sh -c "$TRIGGER" 2>&1 >/dev/null)
  trigger_rc=$?
  if (( trigger_rc != 0 )); then
    echo "  ! trigger exited ${trigger_rc}: ${trigger_err}" >&2
    trial_note="${trial_note:+$trial_note; }trigger exec failed rc=${trigger_rc}"
  fi

  wait_for "$REVOKE_TIMEOUT" "the actuator to revoke" has_revocation \
    || trial_note="${trial_note:+$trial_note; }no revocation within ${REVOKE_TIMEOUT}s"
  wait_for "$DENY_TIMEOUT" "the prober to see a 403" has_deny \
    || trial_note="${trial_note:+$trial_note; }no 403 within ${DENY_TIMEOUT}s"

  # Settle: one compromise emits N events (scenario 2 fires two connects), and
  # the deduped repeats belong in the row's hygiene columns.
  sleep 2

  trial_id="${SCENARIO}-$(date -u +%Y%m%dT%H%M%SZ)"
  raw="$RAW_ROOT/$trial_id"
  mkdir -p "$raw"
  actuator_logs   > "$raw/actuator.log"
  prober_logs     > "$raw/service-a.log"
  translator_logs > "$raw/translator.log"

  python3 "$ROOT/scripts/trial_record.py" \
    --scenario "$SCENARIO" --raw-dir "$raw" --csv "$CSV" \
    --trial-id "$trial_id" --note "$trial_note"
done

echo
echo "CSV:  $CSV"
echo "raw:  $RAW_ROOT"
