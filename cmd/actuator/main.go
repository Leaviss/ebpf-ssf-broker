package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Leaviss/ebpf-ssf-broker/internal/caep"
	"github.com/Leaviss/ebpf-ssf-broker/internal/metrics"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

// Timing headers the translator sets on the POST (cmd/translator/main.go). T0
// arrives inside the SET; T1 and T3 ride here so this process can compute every
// span without a cross-process log join.
const (
	headerT1 = "X-Zta-T1-Ns"
	headerT3 = "X-Zta-T3-Ns"
)

func main() {
	// Spans are sub-second; slog's default whole-second local stamps will not
	// join with the prober's log (scripts/trial_record.py). RFC3339Nano, UTC —
	// same handler as cmd/service-a.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				a.Value = slog.StringValue(a.Value.Time().UTC().Format(time.RFC3339Nano))
			}
			return a
		},
	})))

	slog.Info("Actuator entry point.")
	eventsAddr := os.Getenv("LISTEN_ADDR")

	// Identities already revoked by this process (see revokeInMesh). Owned here
	// rather than by the handler closure so resetDedupeHandler can clear it
	// between trials without restarting the process.
	revoked := &sync.Map{}

	// Started before the Kubernetes client so a misconfigured cluster still
	// leaves a scrape target to look at.
	metrics.Serve(getenv("METRICS_ADDR", ":9091"), metrics.Route{
		Pattern: resetDedupePath,
		Handler: resetDedupeHandler(revoked),
	})

	// The AuthorizationPolicy the actuator appends revoked principals to —
	// deploy/istio/authorization-policy-deny-revoked.yaml.
	namespace := getenv("POLICY_NAMESPACE", "zta-ssf")
	policyName := getenv("POLICY_NAME", "revoked-identities")

	// In-cluster only: the actuator patches through its ServiceAccount, whose
	// RBAC is in deploy/workloads/actuator.yaml.
	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Error("Failed to load in-cluster config", "error", err)
		os.Exit(1)
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		slog.Error("Failed to build Kubernetes dynamic client", "error", err)
		os.Exit(1)
	}
	slog.Info("Kubernetes client ready", "policy", namespace+"/"+policyName)

	http.HandleFunc("/events", eventsHandler(client, revoked, namespace, policyName))
	http.ListenAndServe(eventsAddr, nil)
}

// resetDedupePath is the lab-control endpoint scripts/actuator-reset.sh POSTs
// to between trials.
const resetDedupePath = "/admin/reset-dedupe"

// resetDedupeHandler clears the in-memory revoked set, returning this process to
// its pre-trial state without restarting it.
//
// Restarting would clear the set too, and destroys the measurement: the trial
// then runs in a pod that lives about as long as the trial itself (~12s), so
// most pods are scraped once or never, and a single scrape is a coin flip on
// whether it landed before or after the PATCH. Counters only mean anything if
// the process holding them outlives what they count (docs/trial-reset.md).
//
// POST-only, so a stray scrape or a browser preflight cannot silently clear the
// set mid-trial. Unauthenticated: lab tooling on a port with no Service in front
// of it, named as a caveat in the README rather than hardened.
func resetDedupeHandler(revoked *sync.Map) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cleared := 0
		revoked.Range(func(key, _ any) bool {
			revoked.Delete(key)
			cleared++
			return true
		})

		// Logged at Info with a count so the reset is visible in the same log
		// stream as the trial it precedes — a trial that dedupes unexpectedly can
		// then be told apart from one whose reset never landed.
		slog.Info("Dedupe set cleared", "cleared", cleared)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "cleared %d\n", cleared)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// eventsHandler is the RFC 8935 SET receiver: it decodes the SET, takes the
// already-resolved SPIFFE ID from its subject, and actuates the revocation.
// `revoked` is the per-identity dedupe set (see revokeInMesh), passed in so that
// this handler and resetDedupeHandler share the one instance.
func eventsHandler(client dynamic.Interface, revoked *sync.Map, namespace, policyName string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// T4 — handler entry. First statement in the handler so the `transport`
		// span (T4-T3) measures the hop and not this handler's own validation.
		t4 := time.Now()

		if req.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(req.Body)
		defer req.Body.Close()
		if err != nil {
			slog.Error("Failed to read request body", "error", err)
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}

		claims, err := caep.DecodeUnsigned(string(body))
		if err != nil {
			// Counted as `failed`: a SET arrived and nothing was revoked, which
			// the success rate has to account for. An undecodable SET has no
			// subject, so it can be counted no other way.
			eventsTotal.WithLabelValues("failed").Inc()
			slog.Error("Failed to decode SET", "error", err)
			http.Error(w, "malformed SET", http.StatusBadRequest)
			return
		}

		spiffeSubject := claims.SubId.URI

		// The translator's clocks: T0 off the SET, T1/T3 off the headers. Any may
		// be absent (a hand-crafted SET, an older translator) — spans that depend
		// on a missing stamp are omitted rather than logged as zero.
		t0 := nsToTime(claims.Events.EventTimeStampNs)
		t1 := headerTime(req.Header, headerT1)
		t3 := headerTime(req.Header, headerT3)

		slog.Info("Subject compromised:",
			"SPIFFE Subject", spiffeSubject,
			"jti", claims.ID,
			"t0_ns", claims.Events.EventTimeStampNs,
		)

		// Run in parallel: the mesh patch is the real-time revocation and owns the
		// measured latency, so the SPIRE label removal — complementary, TTL-scale
		// — must never sit in front of it (docs/architecture.md).
		var (
			wg sync.WaitGroup

			patched bool
			meshErr error
			t5, t6  time.Time

			unlabeled int
			labelErr  error
		)

		wg.Add(2)
		go func() {
			defer wg.Done()
			// T5/T6 — the API-server write, bracketed as tightly as possible: the
			// `actuate` span, and the end of what the code can see.
			t5 = time.Now()
			patched, meshErr = revokeInMesh(req.Context(), client, revoked, namespace, policyName, spiffeSubject)
			t6 = time.Now()
		}()
		go func() {
			defer wg.Done()
			unlabeled, labelErr = removeSpireLabel(req.Context(), client, spiffeSubject)
		}()
		wg.Wait()

		// The label removal is not the revocation, so a failure there is logged
		// but does not fail the event — the mesh deny still stands.
		if labelErr != nil {
			slog.Error("Failed to remove SPIRE-managed label", "error", labelErr, "subject", spiffeSubject)
		} else if unlabeled > 0 {
			slog.Info("SPIRE-managed label removed, identity will not be reissued",
				"subject", spiffeSubject,
				"pods", unlabeled,
			)
		}

		if meshErr != nil {
			eventsTotal.WithLabelValues("failed").Inc()
			slog.Error("Failed to actuate revocation in mesh",
				"error", meshErr,
				"subject", spiffeSubject,
				"jti", claims.ID,
			)
			http.Error(w, "actuation failed", http.StatusInternalServerError)
			return
		}

		// The measurement record: one line per event with every timestamp and span
		// this process can see, keyed by jti so it joins against the translator's
		// log and the per-trial CSV. `result` mirrors the
		// zta_revocation_events_total label (metrics.go); a "deduped" row is a
		// hygiene signal, not a pipeline sample.
		msg, result := "Revocation actuated in mesh", "revoked"
		if !patched {
			msg, result = "Subject already revoked, mesh patch skipped", "deduped"
		}
		eventsTotal.WithLabelValues(result).Inc()
		// Only an event that actually actuated is a latency sample (observeSpans).
		// Deduped events still get the log line below, so nothing is lost from the
		// per-trial CSV.
		if patched {
			observeSpans(t0, t1, t3, t4, t5, t6)
		}
		slog.Info(msg,
			append([]any{
				"jti", claims.ID,
				"subject", spiffeSubject,
				"policy", namespace + "/" + policyName,
				"result", result,
			}, pipelineSpans(t0, t1, t3, t4, t5, t6)...)...,
		)

		w.WriteHeader(http.StatusAccepted)
	}
}

// nsToTime converts a Unix-nanosecond stamp to a time, mapping zero to the zero
// time. Without this an absent stamp becomes 1970 and every span computed from
// it is a plausible-looking 56-year number.
func nsToTime(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// headerTime reads one of the translator's Unix-nanosecond timing headers,
// returning the zero time when it is absent or unparseable.
func headerTime(h http.Header, key string) time.Time {
	ns, err := strconv.ParseInt(h.Get(key), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return nsToTime(ns)
}

// pipelineSpans returns the timing spans available to this process as slog
// key/value pairs, and is the source for the per-trial CSV. A span with an
// unknown endpoint is dropped, so a missing upstream clock costs one column
// rather than silently reporting zero.
//
// `enforce` and `end_to_end` are absent: they need T8 from the prober, which
// lives in another process and is joined offline (scripts/trial_record.py).
func pipelineSpans(t0, t1, t3, t4, t5, t6 time.Time) []any {
	stamps := []struct {
		key string
		at  time.Time
	}{
		{"t0_ns", t0}, {"t1_ns", t1}, {"t3_ns", t3},
		{"t4_ns", t4}, {"t5_ns", t5}, {"t6_ns", t6},
	}
	spans := spanTable(t0, t1, t3, t4, t5, t6)

	attrs := make([]any, 0, 2*(len(stamps)+len(spans)))
	for _, s := range stamps {
		if !s.at.IsZero() {
			attrs = append(attrs, s.key, s.at.UnixNano())
		}
	}
	for _, s := range spans {
		if s.known() {
			attrs = append(attrs, s.stage+"_us", s.duration().Microseconds())
		}
	}
	return attrs
}
